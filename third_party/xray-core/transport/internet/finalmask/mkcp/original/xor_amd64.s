#include "textflag.h"


TEXT ·xorfwd(SB),NOSPLIT,$0
  MOVQ x+0(FP), SI
  MOVQ x_len+8(FP), CX
  MOVQ x+0(FP), DI
  ADDQ $4, DI
  SUBQ $4, CX
xorfwdloop:
  MOVL (SI), AX
  XORL AX, (DI)
  ADDQ $4, SI
  ADDQ $4, DI
  SUBQ $4, CX

  CMPL CX, $0
  JE xorfwddone

  JMP xorfwdloop
xorfwddone:        
  RET


TEXT ·xorbkd(SB),NOSPLIT,$0
  MOVQ x+0(FP), SI
  MOVQ x_len+8(FP), CX
  MOVQ x+0(FP), DI
  ADDQ CX, SI
  SUBQ $8, SI
  ADDQ CX, DI
  SUBQ $4, DI
  SUBQ $4, CX
xorbkdloop:
  MOVL (SI), AX
  XORL AX, (DI)
  SUBQ $4, SI
  SUBQ $4, DI
  SUBQ $4, CX

  CMPL CX, $0
  JE xorbkddone
  
  JMP xorbkdloop

xorbkddone:        
  RET
