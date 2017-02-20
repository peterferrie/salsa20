/**
  Copyright © 2016 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include "s20.h"

// setup the key, must be 256-bits with 64-bit nonce
void s20_setkey(s20_ctx *c, void *key, void *nonce)
{
    s20_blk *iv=(s20_blk*)nonce;
    s20_blk *k=(s20_blk*)key;
    
    c->s.w[ 0] = 0x61707865;
    c->s.w[ 1] = k->w[0];
    c->s.w[ 2] = k->w[1];
    c->s.w[ 3] = k->w[2];
    c->s.w[ 4] = k->w[3];
    c->s.w[ 5] = 0x3320646E;
    c->s.w[ 6] = iv->w[0];
    c->s.w[ 7] = iv->w[1];
    c->s.w[ 8] = 0;
    c->s.w[ 9] = 0;
    c->s.w[10] = 0x79622D32;
    c->s.w[11] = k->w[4];
    c->s.w[12] = k->w[5];
    c->s.w[13] = k->w[6];
    c->s.w[14] = k->w[7];
    c->s.w[15] = 0x6B206574;
}

// transforms block using ARX instructions
void s20_permute(s20_blk *blk, uint16_t idx) 
{
    uint32_t a, b, c, d;
    uint32_t *x=(uint32_t*)&blk->b;
    
    a = (idx         & 0xF);
    b = ((idx >>  4) & 0xF);
    c = ((idx >>  8) & 0xF);
    d = ((idx >> 12) & 0xF);

    x[b] ^= ROTL32((x[a] + x[d]), 7);
    x[c] ^= ROTL32((x[b] + x[a]), 9);
    
    x[d] ^= ROTL32((x[c] + x[b]),13);
    x[a] ^= ROTL32((x[d] + x[c]),18);
}

// generate stream of bytes
void s20_stream (s20_ctx *c, s20_blk *x)
{
    int i, j;

    // 16-bit integers of each index
    uint16_t idx16[8]=
    { 0xC840, 0x1D95, 0x62EA, 0xB73F, 
      0x3210, 0x4765, 0x98BA, 0xEDCF };
    
    // copy state to local space
    for (i=0; i<16; i++) { 
      x->w[i] = c->s.w[i];
    }
    // apply 20 rounds
    for (i=0; i<20; i+=2) {
      for (j=0; j<8; j++) {
        s20_permute(x, idx16[j]);
      }
    }
    // add state to x
    for (i=0; i<16; i++) {
      x->w[i] += c->s.w[i];
    }
    // update block counter
    c->s.q[4]++;
    // stopping at 2^70 bytes per nonce is user's responsibility
}

// encrypt or decrypt stream of bytes
void s20_encrypt (uint32_t len, void *buf, s20_ctx *c) 
{
    uint32_t r, i;
    s20_blk  stream;
    uint8_t  *p=(uint8_t*)buf;
    
    while (len) {      
      s20_stream(c, &stream);
      
      r=(len>64) ? 64 : len;
      
      for (i=0; i<r; i++) {
        p[i] ^= stream.b[i];
      }      
      len -= r;
      p += r;
    }
}
