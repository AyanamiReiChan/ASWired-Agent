package strmatcher

import (
	"errors"
	"regexp"
)

type Matcher interface {
	Match(string) bool
	String() string
}

type Type byte

const (
	Full Type = iota

	Substr

	Domain

	Regex
)

func (t Type) New(pattern string) (Matcher, error) {

	switch t {
	case Full:
		return fullMatcher(pattern), nil
	case Substr:
		return substrMatcher(pattern), nil
	case Domain:
		return domainMatcher(pattern), nil
	case Regex:
		r, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return &RegexMatcher{
			Pattern: pattern,
			reg:     r,
		}, nil
	default:
		return nil, errors.New("unk type")
	}
}

type IndexMatcher interface {
	Match(input string) []uint32

	Size() uint32
}

type MatcherEntry struct {
	M  Matcher
	Id uint32
}

type MatcherGroup struct {
	count         uint32
	fullMatcher   FullMatcherGroup
	domainMatcher DomainMatcherGroup
	otherMatchers []MatcherEntry
}

func (g *MatcherGroup) Add(m Matcher) uint32 {
	g.count++
	c := g.count

	switch tm := m.(type) {
	case fullMatcher:
		g.fullMatcher.addMatcher(tm, c)
	case domainMatcher:
		g.domainMatcher.addMatcher(tm, c)
	default:
		g.otherMatchers = append(g.otherMatchers, MatcherEntry{
			M:  m,
			Id: c,
		})
	}

	return c
}

func (g *MatcherGroup) Match(pattern string) []uint32 {
	result := []uint32{}
	result = append(result, g.fullMatcher.Match(pattern)...)
	result = append(result, g.domainMatcher.Match(pattern)...)
	for _, e := range g.otherMatchers {
		if e.M.Match(pattern) {
			result = append(result, e.Id)
		}
	}
	return result
}

func (g *MatcherGroup) Size() uint32 {
	return g.count
}

type IndexMatcherGroup struct {
	Matchers []IndexMatcher
}

func (g *IndexMatcherGroup) Match(input string) []uint32 {
	var offset uint32
	for _, m := range g.Matchers {
		if res := m.Match(input); len(res) > 0 {
			if offset == 0 {
				return res
			}
			shifted := make([]uint32, len(res))
			for i, id := range res {
				shifted[i] = id + offset
			}
			return shifted
		}
		offset += m.Size()
	}
	return nil
}

func (g *IndexMatcherGroup) Size() uint32 {
	var count uint32
	for _, m := range g.Matchers {
		count += m.Size()
	}
	return count
}
