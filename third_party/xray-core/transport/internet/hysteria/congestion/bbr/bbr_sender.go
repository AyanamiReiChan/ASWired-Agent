package bbr

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/common"
)

const (
	minBps = 65536

	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32

	defaultMinimumCongestionWindow = 4 * congestion.ByteCount(congestion.InitialPacketSize)

	defaultHighGain = 2.885

	derivedHighGain = 2.773

	derivedHighCWNDGain = 2.0

	debugEnv = "HYSTERIA_BBR_DEBUG"
)

var pacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	gainCycleLength = len(pacingGain)

	bandwidthWindowSize = gainCycleLength + 2

	minRttExpiry = 10 * time.Second

	probeRttTime = 200 * time.Millisecond

	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	defaultStartupFullLossCount  = 8
	quicBbr2DefaultLossThreshold = 0.02
	maxBbrBurstPackets           = 10
)

type bbrMode int

const (
	bbrModeStartup = iota

	bbrModeDrain

	bbrModeProbeBw

	bbrModeProbeRtt
)

type bbrRecoveryState int

const (
	bbrRecoveryStateNotInRecovery = iota

	bbrRecoveryStateConservation

	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats congestion.RTTStatsProvider
	clock    Clock
	pacer    *common.Pacer

	mode bbrMode

	sampler *bandwidthSampler

	roundTripCount roundTripCount

	lastSentPacket congestion.PacketNumber

	currentRoundTripEnd congestion.PacketNumber

	numLossEventsInRound uint64

	bytesLostInRound congestion.ByteCount

	maxBandwidth *WindowedFilter[Bandwidth, roundTripCount]

	minRtt time.Duration

	minRttTimestamp monotime.Time

	congestionWindow congestion.ByteCount

	initialCongestionWindow congestion.ByteCount

	maxCongestionWindow congestion.ByteCount

	minCongestionWindow congestion.ByteCount

	highGain float64

	highCwndGain float64

	drainGain float64

	pacingRate Bandwidth

	pacingGain float64

	congestionWindowGain float64

	congestionWindowGainConstant float64

	numStartupRtts int64

	cycleCurrentOffset int

	lastCycleStart monotime.Time

	isAtFullBandwidth bool

	roundsWithoutBandwidthGain int64

	bandwidthAtLastRound Bandwidth

	exitingQuiescence bool

	exitProbeRttAt monotime.Time

	probeRttRoundPassed bool

	lastSampleIsAppLimited bool

	hasNoAppLimitedSample bool

	recoveryState bbrRecoveryState

	endRecoveryAt congestion.PacketNumber

	recoveryWindow congestion.ByteCount

	isAppLimitedRecovery bool

	slowerStartup bool

	rateBasedStartup bool

	enableAckAggregationDuringStartup bool

	expireAckAggregationInStartup bool

	drainToTarget bool

	detectOvershooting bool

	bytesLostWhileDetectingOvershooting congestion.ByteCount

	bytesLostMultiplierWhileDetectingOvershooting uint8

	cwndToCalculateMinPacingRate congestion.ByteCount

	maxCongestionWindowWithNetworkParametersAdjusted congestion.ByteCount

	maxDatagramSize congestion.ByteCount

	bytesInFlight congestion.ByteCount

	debug bool
}

var _ congestion.CongestionControl = &bbrSender{}

func NewBbrSender(
	clock Clock,
	initialMaxDatagramSize congestion.ByteCount,
) *bbrSender {
	return newBbrSender(
		clock,
		initialMaxDatagramSize,
		initialCongestionWindowPackets*initialMaxDatagramSize,
		congestion.MaxCongestionWindowPackets*initialMaxDatagramSize,
	)
}

func newBbrSender(
	clock Clock,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow congestion.ByteCount,
) *bbrSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	b := &bbrSender{
		clock:                        clock,
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               invalidPacketNumber,
		currentRoundTripEnd:          invalidPacketNumber,
		maxBandwidth:                 NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth]),
		congestionWindow:             initialCongestionWindow,
		initialCongestionWindow:      initialCongestionWindow,
		maxCongestionWindow:          initialMaxCongestionWindow,
		minCongestionWindow:          defaultMinimumCongestionWindow,
		highGain:                     defaultHighGain,
		highCwndGain:                 defaultHighGain,
		drainGain:                    1.0 / defaultHighGain,
		pacingGain:                   1.0,
		congestionWindowGain:         1.0,
		congestionWindowGainConstant: 2.0,
		numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:                bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                invalidPacketNumber,
		recoveryWindow:               initialMaxCongestionWindow,
		bytesLostMultiplierWhileDetectingOvershooting:    2,
		cwndToCalculateMinPacingRate:                     initialCongestionWindow,
		maxCongestionWindowWithNetworkParametersAdjusted: initialMaxCongestionWindow,
		maxDatagramSize: initialMaxDatagramSize,
		debug:           debug,
	}
	b.pacer = common.NewPacer(b.bandwidthForPacer)

	b.enterStartupMode(b.clock.Now())
	b.setHighCwndGain(derivedHighCWNDGain)

	return b
}

func (b *bbrSender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	b.rttStats = provider
}

func (b *bbrSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

func (b *bbrSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) MaybeExitSlowStart() {

}

func (b *bbrSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes, priorInFlight congestion.ByteCount, eventTime monotime.Time) {

}

func (b *bbrSender) OnPacketLost(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {

}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {

}

func (b *bbrSender) SetMaxDatagramSize(s congestion.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	cwndIsMinCwnd := b.congestionWindow == b.minCongestionWindow
	b.maxDatagramSize = s
	if cwndIsMinCwnd {
		b.congestionWindow = b.minCongestionWindow
	}
	b.pacer.SetMaxDatagramSize(s)
}

func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

func (b *bbrSender) GetCongestionWindow() congestion.ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	if b.InRecovery() {
		return min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

func (b *bbrSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {

}

func (b *bbrSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	var isRoundStart, minRttExpired bool
	var excessAcked, bytesLost congestion.ByteCount

	var lastPacketSendState sendTimeState

	b.maybeAppLimited(priorInFlight)

	b.bytesInFlight = priorInFlight
	for _, p := range ackedPackets {
		b.bytesInFlight -= p.BytesAcked
	}
	for _, p := range lostPackets {
		b.bytesInFlight -= p.BytesLost
	}

	if len(ackedPackets) != 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].PacketNumber
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
		b.updateRecoveryState(lastAckedPacket, len(lostPackets) != 0, isRoundStart)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		ackedPackets, lostPackets, b.maxBandwidth.GetBest(), infBandwidth, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		b.hasNoAppLimitedSample = b.hasNoAppLimitedSample || !b.lastSampleIsAppLimited
	}

	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}
	bytesLost = b.sampler.TotalBytesLost() - totalBytesLostBefore

	excessAcked = sample.extraAcked
	lastPacketSendState = sample.lastPacketSendState

	if len(lostPackets) != 0 {
		b.numLossEventsInRound++
		b.bytesLostInRound += bytesLost
	}

	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) != 0)
	}

	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)

	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore

	b.calculatePacingRate(bytesLost)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	var leastUnacked congestion.PacketNumber
	if len(ackedPackets) != 0 {
		leastUnacked = ackedPackets[len(ackedPackets)-1].PacketNumber - 2
	} else {
		leastUnacked = lostPackets[len(lostPackets)-1].PacketNumber + 1
	}
	b.sampler.RemoveObsoletePackets(leastUnacked)

	if isRoundStart {
		b.numLossEventsInRound = 0
		b.bytesLostInRound = 0
	}
}

func (b *bbrSender) PacingRate() Bandwidth {
	if b.pacingRate == 0 {
		return Bandwidth(b.highGain * float64(
			BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt())))
	}

	return b.pacingRate
}

func (b *bbrSender) hasGoodBandwidthEstimateForResumption() bool {
	return b.hasNonAppLimitedSample()
}

func (b *bbrSender) hasNonAppLimitedSample() bool {
	return b.hasNoAppLimitedSample
}

func (b *bbrSender) setHighGain(highGain float64) {
	b.highGain = highGain
	if b.mode == bbrModeStartup {
		b.pacingGain = highGain
	}
}

func (b *bbrSender) setHighCwndGain(highCwndGain float64) {
	b.highCwndGain = highCwndGain
	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

func (b *bbrSender) setDrainGain(drainGain float64) {
	b.drainGain = drainGain
}

func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.GetBest()
}

func (b *bbrSender) bandwidthForPacer() congestion.ByteCount {
	bps := congestion.ByteCount(float64(b.PacingRate()) / float64(BytesPerSecond))
	if bps < minBps {

		return minBps
	}
	return bps
}

func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}

	minRtt := b.rttStats.MinRTT()
	if minRtt == 0 {
		return 100 * time.Millisecond
	} else {
		return minRtt
	}
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) congestion.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := congestion.ByteCount(gain * float64(bdp))

	if congestionWindow == 0 {
		congestionWindow = congestion.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) probeRttCongestionWindow() congestion.ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now monotime.Time, sampleMinRtt time.Duration) bool {

	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

func (b *bbrSender) enterStartupMode(now monotime.Time) {
	b.mode = bbrModeStartup

	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain

	if b.debug {
		b.debugPrint("Phase: STARTUP")
	}
}

func (b *bbrSender) enterProbeBandwidthMode(now monotime.Time) {
	b.mode = bbrModeProbeBw

	b.congestionWindowGain = b.congestionWindowGainConstant

	b.cycleCurrentOffset = int(rand.Int31n(congestion.PacketsPerConnectionID)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]

	if b.debug {
		b.debugPrint("Phase: PROBE_BW")
	}
}

func (b *bbrSender) updateRoundTripCounter(lastAckedPacket congestion.PacketNumber) bool {
	if b.currentRoundTripEnd == invalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

func (b *bbrSender) updateGainCyclePhase(now monotime.Time, priorInFlight congestion.ByteCount, hasLosses bool) {

	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))

	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now

		if b.drainToTarget && b.pacingGain < 1 &&
			pacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight > b.getTargetCongestionWindow(1) {
			return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {

			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeAppLimited(bytesInFlight congestion.ByteCount) {
	if bytesInFlight < b.getTargetCongestionWindow(1) {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) maybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain

		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain

		if b.debug {
			b.debugPrint("Phase: DRAIN")
		}
	}
	if b.mode == bbrModeDrain && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) maybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt

		b.pacingGain = 1.0

		b.exitProbeRttAt = 0

		if b.debug {
			b.debugPrint("BandwidthEstimate: %s, CongestionWindowGain: %.2f, PacingGain: %.2f, PacingRate: %s",
				formatSpeed(b.bandwidthEstimate()), b.congestionWindowGain, b.pacingGain, formatSpeed(b.PacingRate()))
			b.debugPrint("Phase: PROBE_RTT")
		}
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.OnAppLimited()

		if b.exitProbeRttAt.IsZero() {

			if b.bytesInFlight < b.probeRttCongestionWindow()+congestion.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if b.debug {
					b.debugPrint("MinRTT: %s", b.getMinRtt())
				}
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

func (b *bbrSender) updateRecoveryState(lastAckedPacket congestion.PacketNumber, hasLosses, isRoundStart bool) {

	if !b.isAtFullBandwidth {
		return
	}

	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation

			b.recoveryWindow = 0

			b.currentRoundTripEnd = b.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:

		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

func (b *bbrSender) calculatePacingRate(bytesLost congestion.ByteCount) {
	if b.bandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	if b.pacingRate == 0 && b.rttStats.MinRTT() != 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}

	if b.detectOvershooting {
		b.bytesLostWhileDetectingOvershooting += bytesLost

		if b.pacingRate > targetRate && b.bytesLostWhileDetectingOvershooting > 0 {
			if b.hasNoAppLimitedSample ||
				b.bytesLostWhileDetectingOvershooting*congestion.ByteCount(b.bytesLostMultiplierWhileDetectingOvershooting) > b.initialCongestionWindow {

				b.pacingRate = max(targetRate, BandwidthFromDelta(b.cwndToCalculateMinPacingRate, b.rttStats.MinRTT()))
				b.bytesLostWhileDetectingOvershooting = 0
				b.detectOvershooting = false
			}
		}
	}

	b.pacingRate = max(b.pacingRate, targetRate)
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked congestion.ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {

		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {

		targetWindow += excessAcked
	}

	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {

		b.congestionWindow += bytesAcked
	}

	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost congestion.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight + bytesAcked
		b.recoveryWindow = max(b.minCongestionWindow, b.recoveryWindow)
		return
	}

	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow = b.recoveryWindow - bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	b.recoveryWindow = max(b.recoveryWindow, b.bytesInFlight+bytesAcked)
	b.recoveryWindow = max(b.minCongestionWindow, b.recoveryWindow)
}

func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}

	inflightAtSend := lastPacketSendState.bytesInFlight

	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		if b.bytesLostInRound > congestion.ByteCount(float64(inflightAtSend)*quicBbr2DefaultLossThreshold) {
			return true
		}
		return false
	}
	return false
}

func (b *bbrSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BBRSender] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) congestion.ByteCount {
	return congestion.ByteCount(rtt) * congestion.ByteCount(bandwidth) / congestion.ByteCount(BytesPerSecond) / congestion.ByteCount(time.Second)
}

func GetInitialPacketSize(addr net.Addr) congestion.ByteCount {

	if _, ok := addr.(*net.UDPAddr); ok {
		return congestion.InitialPacketSize
	} else {
		return congestion.MinInitialPacketSize
	}
}

func formatSpeed(bw Bandwidth) string {
	bwf := float64(bw)
	units := []string{"bps", "Kbps", "Mbps", "Gbps"}
	unitIndex := 0
	for bwf > 1000 && unitIndex < len(units)-1 {
		bwf /= 1000
		unitIndex++
	}
	return fmt.Sprintf("%.2f %s", bwf, units[unitIndex])
}
