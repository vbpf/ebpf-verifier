
objs/cilium/bpf_lxc.o:	file format ELF64-BPF

Disassembly of section .text:
ipv6_l3_from_lxc:
; {
       0:	r8 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 244920237338078 ll
       3:	*(u64 *)(r10 - 144) = r1
       4:	r1 = 0
; struct lb6_key key = {};
       5:	*(u32 *)(r10 - 152) = r1
       6:	*(u64 *)(r10 - 160) = r1
       7:	*(u64 *)(r10 - 168) = r1
       8:	r9 = 4294967166 ll
; tmp = a->p1 - b->p1;
      10:	r1 = *(u32 *)(r3 + 6)
; if (!tmp)
      11:	r0 = 3721182122 ll
      13:	if r1 != r0 goto +171 <LBB13_37>
; tmp = a->p2 - b->p2;
      14:	r1 = *(u16 *)(r3 + 10)
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	if r1 != 65518 goto +169 <LBB13_37>
      16:	r9 = 4294967165 ll
; tmp = a->p1 - b->p1;
      18:	r1 = *(u32 *)(r3 + 0)
; if (!tmp)
      19:	r0 = 4022250974 ll
      21:	if r1 != r0 goto +163 <LBB13_37>
; tmp = a->p2 - b->p2;
      22:	r1 = *(u16 *)(r3 + 4)
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	if r1 != 57024 goto +161 <LBB13_37>
      24:	r9 = 4294967164 ll
; tmp = a->p1 - b->p1;
      26:	r1 = *(u32 *)(r4 + 8)
; if (!tmp) {
      27:	if r1 != 61374 goto +157 <LBB13_37>
; tmp = a->p2 - b->p2;
      28:	r1 = *(u32 *)(r4 + 12)
; if (!tmp) {
      29:	if r1 != 0 goto +155 <LBB13_37>
; tmp = a->p3 - b->p3;
      30:	r1 = *(u32 *)(r4 + 16)
; if (!tmp)
      31:	if r1 != 16777216 goto +153 <LBB13_37>
; tmp = a->p4 - b->p4;
      32:	r1 = *(u32 *)(r4 + 20)
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r3 = 3162662145 ll
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	if r1 != r3 goto +149 <LBB13_37>
      36:	*(u64 *)(r10 - 208) = r5
; dst->p1 = src->p1;
      37:	r1 = *(u32 *)(r4 + 24)
      38:	*(u32 *)(r2 + 0) = r1
; dst->p2 = src->p2;
      39:	r1 = *(u32 *)(r4 + 28)
      40:	*(u32 *)(r2 + 4) = r1
; dst->p3 = src->p3;
      41:	r1 = *(u32 *)(r4 + 32)
      42:	*(u32 *)(r2 + 8) = r1
; dst->p4 = src->p4;
      43:	r1 = *(u32 *)(r4 + 36)
      44:	*(u32 *)(r2 + 12) = r1
; dst->p1 = src->p1;
      45:	r1 = *(u32 *)(r4 + 8)
      46:	*(u32 *)(r2 + 16) = r1
; dst->p2 = src->p2;
      47:	r1 = *(u32 *)(r4 + 12)
      48:	*(u32 *)(r2 + 20) = r1
; dst->p3 = src->p3;
      49:	r1 = *(u32 *)(r4 + 16)
      50:	*(u32 *)(r2 + 24) = r1
; dst->p4 = src->p4;
      51:	r1 = *(u32 *)(r4 + 20)
      52:	*(u32 *)(r2 + 28) = r1
      53:	r7 = 40
      54:	*(u64 *)(r10 - 200) = r2
; __u8 nh = *nexthdr;
      55:	r1 = *(u8 *)(r2 + 36)
; switch (nh) {
      56:	if r1 > 60 goto +105 <LBB13_33>
      57:	r2 = 1
      58:	r2 <<= r1
      59:	r3 = 1155182100513554433 ll
      61:	r2 &= r3
      62:	if r2 != 0 goto +5 <LBB13_12>
      63:	if r1 == 44 goto +119 <LBB13_36>
      64:	r9 = 4294967140 ll
      66:	if r1 == 59 goto +118 <LBB13_37>
      67:	goto +94 <LBB13_33>

LBB13_12:
      68:	r3 = r10
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r3 += -96
      70:	r7 = 2
      71:	r1 = r8
      72:	r2 = 54
      73:	r4 = 2
      74:	call 26
      75:	r9 = 4294967162 ll
      77:	r0 <<= 32
      78:	r0 s>>= 32
      79:	if r0 s< 0 goto +105 <LBB13_37>
; nh = opthdr.nexthdr;
      80:	r1 = *(u8 *)(r10 - 96)
; if (nh == NEXTHDR_AUTH)
      81:	if r1 == 51 goto +1 <LBB13_15>
      82:	r7 = 3

LBB13_15:
      83:	r6 = *(u8 *)(r10 - 95)
      84:	r6 <<= r7
      85:	r7 = r6
      86:	r7 += 48
; switch (nh) {
      87:	if r1 > 60 goto +74 <LBB13_33>
      88:	r2 = 1
      89:	r2 <<= r1
      90:	r3 = 1155182100513554433 ll
      92:	r2 &= r3
      93:	if r2 != 0 goto +5 <LBB13_19>
      94:	if r1 == 44 goto +88 <LBB13_36>
      95:	r9 = 4294967140 ll
      97:	if r1 == 59 goto +87 <LBB13_37>
      98:	goto +63 <LBB13_33>

LBB13_19:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r2 = r6
     100:	r2 += 62
     101:	r3 = r10
     102:	r3 += -96
     103:	r7 = 2
     104:	r1 = r8
     105:	r4 = 2
     106:	call 26
     107:	r0 <<= 32
     108:	r0 s>>= 32
     109:	if r0 s< 0 goto +75 <LBB13_37>
; nh = opthdr.nexthdr;
     110:	r1 = *(u8 *)(r10 - 96)
; if (nh == NEXTHDR_AUTH)
     111:	if r1 == 51 goto +1 <LBB13_22>
     112:	r7 = 3

LBB13_22:
     113:	r2 = *(u8 *)(r10 - 95)
     114:	r2 <<= r7
     115:	r6 += r2
     116:	r6 += 56
     117:	r7 = r6
; switch (nh) {
     118:	if r1 > 60 goto +43 <LBB13_33>
     119:	r2 = 1
     120:	r2 <<= r1
     121:	r3 = 1155182100513554433 ll
     123:	r2 &= r3
     124:	if r2 != 0 goto +6 <LBB13_26>
     125:	if r1 == 44 goto +57 <LBB13_36>
     126:	r9 = 4294967140 ll
     128:	r7 = r6
     129:	if r1 == 59 goto +55 <LBB13_37>
     130:	goto +31 <LBB13_33>

LBB13_26:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r2 = r6
     132:	r2 += 14
     133:	r3 = r10
     134:	r3 += -96
     135:	r7 = 2
     136:	r1 = r8
     137:	r4 = 2
     138:	call 26
     139:	r0 <<= 32
     140:	r0 s>>= 32
     141:	if r0 s< 0 goto +43 <LBB13_37>
; nh = opthdr.nexthdr;
     142:	r1 = *(u8 *)(r10 - 96)
; if (nh == NEXTHDR_AUTH)
     143:	if r1 == 51 goto +1 <LBB13_29>
     144:	r7 = 3

LBB13_29:
     145:	r2 = *(u8 *)(r10 - 95)
     146:	r2 <<= r7
     147:	r6 += r2
     148:	r6 += 8
     149:	r7 = r6
; switch (nh) {
     150:	if r1 > 60 goto +11 <LBB13_33>
     151:	r2 = 1
     152:	r2 <<= r1
     153:	r3 = 1155182100513554433 ll
     155:	r2 &= r3
     156:	if r2 != 0 goto +249 <LBB13_69>
     157:	if r1 == 44 goto +25 <LBB13_36>
     158:	r9 = 4294967140 ll
     160:	r7 = r6
     161:	if r1 == 59 goto +23 <LBB13_37>

LBB13_33:
     162:	r3 = *(u64 *)(r10 - 200)
; *nexthdr = nh;
     163:	*(u8 *)(r3 + 36) = r1
; dst->p1 = src->p1;
     164:	r2 = *(u32 *)(r3 + 0)
     165:	*(u32 *)(r10 - 168) = r2
; dst->p2 = src->p2;
     166:	r2 = *(u32 *)(r3 + 4)
     167:	*(u32 *)(r10 - 164) = r2
; dst->p3 = src->p3;
     168:	r2 = *(u32 *)(r3 + 8)
     169:	*(u32 *)(r10 - 160) = r2
; dst->p4 = src->p4;
     170:	r2 = *(u32 *)(r3 + 12)
     171:	*(u32 *)(r10 - 156) = r2
     172:	r9 = 4294967154 ll
     174:	r2 = 0
; switch (nexthdr) {
     175:	*(u64 *)(r10 - 272) = r2
     176:	if r1 s> 16 goto +10 <LBB13_38>
     177:	r6 = 0
     178:	if r1 == 1 goto +32 <LBB13_44>
     179:	r6 = 16
     180:	r2 = 0
     181:	if r1 == 6 goto +11 <LBB13_41>
     182:	goto +30 <LBB13_45>

LBB13_36:
     183:	r9 = 4294967139 ll

LBB13_37:
; }
     185:	r0 = r9
     186:	exit

LBB13_38:
; switch (nexthdr) {
     187:	if r1 == 58 goto +192 <LBB13_66>
     188:	r2 = 0
     189:	if r1 != 17 goto +23 <LBB13_45>
     190:	r1 = 32
     191:	*(u64 *)(r10 - 272) = r1
     192:	r6 = 6

LBB13_41:
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r2 = r7
     194:	r2 += 16
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r3 = r10
     196:	r3 += -152
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r1 = r8
     198:	r4 = 2
     199:	call 26
     200:	r9 = r0
     201:	r1 = r9
     202:	r1 <<= 32
     203:	r1 >>= 32
; if (IS_ERR(ret))
     204:	r2 = 1
     205:	if r1 == 2 goto +1 <LBB13_43>
     206:	r2 = 0

LBB13_43:
     207:	r1 >>= 31
     208:	r1 |= r2
     209:	r2 = r6
     210:	if r1 != 0 goto +2 <LBB13_45>

LBB13_44:
     211:	r9 = 0
     212:	r2 = r6

LBB13_45:
     213:	*(u64 *)(r10 - 304) = r2
; if (IS_ERR(ret)) {
     214:	r1 = r9
     215:	r1 <<= 32
     216:	r1 >>= 32
     217:	r2 = 1
     218:	if r1 == 2 goto +1 <LBB13_47>
     219:	r2 = 0

LBB13_47:
     220:	r3 = r7
     221:	r3 += 14
     222:	*(u64 *)(r10 - 232) = r3
     223:	r1 >>= 31
     224:	r1 |= r2
     225:	*(u64 *)(r10 - 224) = r7
     226:	if r1 == 0 goto +14 <LBB13_49>
     227:	r1 = 0
; if (ret == DROP_UNKNOWN_L4)
     228:	*(u64 *)(r10 - 256) = r1
     229:	r1 = r9
     230:	r1 <<= 32
     231:	r1 >>= 32
     232:	r2 = 4294967154 ll
     234:	r3 = 0
     235:	*(u64 *)(r10 - 248) = r3
     236:	r3 = 0
     237:	*(u64 *)(r10 - 264) = r3
     238:	r6 = *(u64 *)(r10 - 200)
     239:	if r1 == r2 goto +456 <LBB13_99>
     240:	goto -56 <LBB13_37>

LBB13_49:
; if (key->dport) {
     241:	r6 = *(u16 *)(r10 - 152)
     242:	if r6 == 0 goto +32 <LBB13_53>
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r7 = *(u32 *)(r10 - 156)
; uint32_t hash = get_hash_recalc(skb);
     244:	r1 = r8
     245:	call 34
; struct debug_msg msg = {
     246:	*(u32 *)(r10 - 92) = r0
     247:	r1 = 269489666
     248:	*(u32 *)(r10 - 96) = r1
     249:	*(u32 *)(r10 - 88) = r7
     250:	r7 = *(u64 *)(r10 - 224)
     251:	*(u32 *)(r10 - 84) = r6
     252:	r6 = 0
     253:	*(u32 *)(r10 - 80) = r6
     254:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r1 = r8
     257:	r2 = 0 ll
     259:	r3 = 4294967295 ll
     261:	r5 = 20
     262:	call 25
     263:	r2 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r2 += -168
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	r1 = 0 ll
     267:	call 1
; if (svc && svc->count != 0)
     268:	if r0 == 0 goto +5 <LBB13_52>
     269:	r1 = *(u8 *)(r0 + 18)
     270:	r2 = *(u8 *)(r0 + 19)
     271:	r2 <<= 8
     272:	r2 |= r1
     273:	if r2 != 0 goto +58 <LBB13_56>

LBB13_52:
; key->dport = 0;
     274:	*(u16 *)(r10 - 152) = r6

LBB13_53:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r6 = *(u32 *)(r10 - 156)
; uint32_t hash = get_hash_recalc(skb);
     276:	r1 = r8
     277:	call 34
; struct debug_msg msg = {
     278:	*(u32 *)(r10 - 92) = r0
     279:	r1 = 269489666
     280:	*(u32 *)(r10 - 96) = r1
     281:	*(u32 *)(r10 - 88) = r6
     282:	r9 = 0
     283:	*(u32 *)(r10 - 84) = r9
     284:	*(u32 *)(r10 - 80) = r9
     285:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r1 = r8
     288:	r2 = 0 ll
     290:	r3 = 4294967295 ll
     292:	r5 = 20
     293:	call 25
     294:	r2 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	r2 += -168
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r1 = 0 ll
     298:	call 1
; if (svc && svc->count != 0)
     299:	if r0 == 0 goto +5 <LBB13_55>
     300:	r1 = *(u8 *)(r0 + 18)
     301:	r2 = *(u8 *)(r0 + 19)
     302:	r2 <<= 8
     303:	r2 |= r1
     304:	if r2 != 0 goto +27 <LBB13_56>

LBB13_55:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r6 = *(u32 *)(r10 - 160)
     306:	r7 = *(u32 *)(r10 - 164)
; uint32_t hash = get_hash_recalc(skb);
     307:	r1 = r8
     308:	call 34
; struct debug_msg msg = {
     309:	*(u32 *)(r10 - 92) = r0
     310:	r1 = 269489922
     311:	*(u32 *)(r10 - 96) = r1
     312:	*(u32 *)(r10 - 88) = r7
     313:	*(u32 *)(r10 - 84) = r6
     314:	r1 = 0
     315:	*(u64 *)(r10 - 256) = r1
     316:	*(u32 *)(r10 - 80) = r9
     317:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r1 = r8
     320:	r2 = 0 ll
     322:	r3 = 4294967295 ll
     324:	r5 = 20
     325:	call 25
     326:	r1 = 0
     327:	*(u64 *)(r10 - 248) = r1
     328:	r1 = 0
     329:	*(u64 *)(r10 - 264) = r1
     330:	r6 = *(u64 *)(r10 - 200)
     331:	goto +364 <LBB13_99>

LBB13_56:
     332:	r6 = *(u64 *)(r10 - 200)
; __u8 flags = tuple->flags;
     333:	r9 = *(u8 *)(r6 + 37)
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	r2 = *(u8 *)(r6 + 36)
; union tcp_flags tcp_flags = { 0 };
     335:	r1 = 0
     336:	*(u16 *)(r10 - 136) = r1
; tuple->flags = TUPLE_F_SERVICE;
     337:	r1 = 4
     338:	*(u8 *)(r6 + 37) = r1
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r1 = 0 ll
     341:	if r2 == 6 goto +2 <LBB13_58>
     342:	r1 = 0 ll

LBB13_58:
     344:	*(u64 *)(r10 - 240) = r1
; switch (tuple->nexthdr) {
     345:	*(u64 *)(r10 - 280) = r0
     346:	*(u64 *)(r10 - 256) = r2
     347:	if r2 == 6 goto +34 <LBB13_67>
     348:	if r2 == 17 goto +82 <LBB13_72>
     349:	if r2 != 58 goto +326 <LBB13_93>
     350:	r3 = r10
; __u8 type;
     351:	r3 += -96
     352:	r1 = 1
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	*(u64 *)(r10 - 288) = r1
     354:	r1 = r8
     355:	r2 = *(u64 *)(r10 - 232)
     356:	r4 = 1
     357:	call 26
     358:	r0 <<= 32
     359:	r0 s>>= 32
     360:	if r0 s< 0 goto +315 <LBB13_93>
     361:	r1 = 0
; tuple->dport = 0;
     362:	*(u8 *)(r6 + 33) = r1
     363:	*(u8 *)(r6 + 32) = r1
; tuple->sport = 0;
     364:	*(u8 *)(r6 + 35) = r1
     365:	*(u8 *)(r6 + 34) = r1
     366:	r1 = *(u8 *)(r10 - 96)
; switch (type) {
     367:	r2 = r1
     368:	r2 += -1
     369:	if r2 < 4 goto +50 <LBB13_70>
     370:	if r1 == 128 goto +55 <LBB13_71>
     371:	if r1 == 129 goto +1 <LBB13_65>
     372:	goto +69 <LBB13_73>

LBB13_65:
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r1 = 128
     374:	*(u8 *)(r6 + 32) = r1
     375:	r2 = 0
     376:	r1 = 0
     377:	*(u64 *)(r10 - 288) = r1
     378:	*(u8 *)(r6 + 33) = r2
     379:	goto +62 <LBB13_73>

LBB13_66:
     380:	r6 = 2
     381:	goto -171 <LBB13_44>

LBB13_67:
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	r2 = r7
     383:	r2 += 26
     384:	r3 = r10
     385:	r3 += -136
     386:	r1 = r8
     387:	r4 = 2
     388:	call 26
     389:	r0 <<= 32
     390:	r0 s>>= 32
     391:	if r0 s< 0 goto +284 <LBB13_93>
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     392:	r7 = *(u8 *)(r10 - 136)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	r3 = r6
     394:	r3 += 32
     395:	r1 = r8
     396:	r2 = *(u64 *)(r10 - 232)
     397:	r4 = 4
     398:	call 26
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	r7 &= 1
     400:	r7 += 1
     401:	*(u64 *)(r10 - 288) = r7
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r0 <<= 32
     403:	r0 s>>= 32
     404:	if r0 s< 0 goto +271 <LBB13_93>
     405:	goto +36 <LBB13_73>

LBB13_69:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	r6 += 14
     407:	r3 = r10
     408:	r3 += -96
     409:	r1 = r8
     410:	r2 = r6
     411:	r4 = 2
     412:	call 26
     413:	r9 = r0
     414:	r9 <<= 32
     415:	r9 s>>= 32
     416:	r9 >>= 31
     417:	r9 &= 22
     418:	r9 += -156
     419:	goto -235 <LBB13_37>

LBB13_70:
; tuple->flags |= TUPLE_F_RELATED;
     420:	r1 = *(u8 *)(r6 + 37)
     421:	r1 |= 2
     422:	*(u8 *)(r6 + 37) = r1
     423:	r1 = 0
; break;
     424:	*(u64 *)(r10 - 288) = r1
     425:	goto +16 <LBB13_73>

LBB13_71:
; tuple->sport = type;
     426:	r1 = 0
     427:	*(u8 *)(r6 + 35) = r1
     428:	r1 = 128
     429:	*(u8 *)(r6 + 34) = r1
     430:	goto +11 <LBB13_73>

LBB13_72:
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	r3 = r6
     432:	r3 += 32
     433:	r1 = r8
     434:	r2 = *(u64 *)(r10 - 232)
     435:	r4 = 4
     436:	call 26
     437:	r1 = 1
     438:	*(u64 *)(r10 - 288) = r1
     439:	r0 <<= 32
     440:	r0 s>>= 32
     441:	if r0 s< 0 goto +234 <LBB13_93>

LBB13_73:
     442:	*(u64 *)(r10 - 296) = r9
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	r1 = *(u8 *)(r6 + 29)
     444:	r1 <<= 8
     445:	r2 = *(u8 *)(r6 + 28)
     446:	r1 |= r2
     447:	r4 = *(u8 *)(r6 + 31)
     448:	r4 <<= 8
     449:	r2 = *(u8 *)(r6 + 30)
     450:	r4 |= r2
     451:	r2 = *(u8 *)(r6 + 13)
     452:	r2 <<= 8
     453:	r3 = *(u8 *)(r6 + 12)
     454:	r2 |= r3
     455:	r9 = *(u8 *)(r6 + 15)
     456:	r9 <<= 8
     457:	r3 = *(u8 *)(r6 + 14)
     458:	r9 |= r3
     459:	r9 <<= 16
     460:	r9 |= r2
     461:	r4 <<= 16
     462:	r4 |= r1
     463:	*(u64 *)(r10 - 264) = r4
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	r7 = *(u8 *)(r6 + 35)
     465:	r7 <<= 8
     466:	r1 = *(u8 *)(r6 + 34)
     467:	r7 |= r1
     468:	r1 = *(u8 *)(r6 + 32)
     469:	*(u64 *)(r10 - 248) = r1
     470:	r6 = *(u8 *)(r6 + 33)
; uint32_t hash = get_hash_recalc(skb);
     471:	r1 = r8
     472:	call 34
; struct debug_msg msg = {
     473:	*(u32 *)(r10 - 92) = r0
     474:	r1 = 269496066
     475:	*(u32 *)(r10 - 96) = r1
     476:	r1 = *(u64 *)(r10 - 264)
     477:	*(u32 *)(r10 - 88) = r1
     478:	*(u32 *)(r10 - 84) = r9
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	r7 = be32 r7
     480:	r1 = 4294901760 ll
     482:	r7 &= r1
     483:	r6 <<= 8
     484:	r1 = *(u64 *)(r10 - 248)
     485:	r6 |= r1
     486:	r6 = be16 r6
     487:	r7 |= r6
; struct debug_msg msg = {
     488:	*(u32 *)(r10 - 80) = r7
     489:	r4 = r10
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     490:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     491:	r1 = r8
     492:	r2 = 0 ll
     494:	r3 = 4294967295 ll
     496:	r5 = 20
     497:	call 25
     498:	r9 = *(u64 *)(r10 - 200)
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     499:	r6 = *(u8 *)(r9 + 37)
     500:	r7 = *(u8 *)(r9 + 36)
; uint32_t hash = get_hash_recalc(skb);
     501:	r1 = r8
     502:	call 34
; struct debug_msg msg = {
     503:	*(u32 *)(r10 - 92) = r0
     504:	r1 = 269496322
     505:	*(u32 *)(r10 - 96) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     506:	r7 <<= 8
     507:	r7 |= r6
; struct debug_msg msg = {
     508:	*(u32 *)(r10 - 88) = r7
     509:	r1 = 0
     510:	*(u32 *)(r10 - 84) = r1
     511:	*(u32 *)(r10 - 80) = r1
     512:	r4 = r10
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     513:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     514:	r1 = r8
     515:	r2 = 0 ll
     517:	r3 = 4294967295 ll
     519:	r5 = 20
     520:	call 25
     521:	r6 = *(u8 *)(r10 - 135)
     522:	r7 = *(u8 *)(r10 - 136)
; if ((entry = map_lookup_elem(map, tuple))) {
     523:	r1 = *(u64 *)(r10 - 240)
     524:	r2 = r9
     525:	call 1
     526:	if r0 == 0 goto +266 <LBB13_113>
     527:	*(u64 *)(r10 - 328) = r7
     528:	*(u64 *)(r10 - 320) = r6
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     529:	r6 = *(u16 *)(r0 + 38)
     530:	*(u64 *)(r10 - 312) = r0
     531:	r1 = *(u64 *)(r10 - 312)
     532:	r7 = *(u32 *)(r1 + 32)
; uint32_t hash = get_hash_recalc(skb);
     533:	r1 = r8
     534:	call 34
; struct debug_msg msg = {
     535:	*(u32 *)(r10 - 92) = r0
     536:	r1 = 269486082
     537:	*(u32 *)(r10 - 96) = r1
     538:	*(u32 *)(r10 - 88) = r7
     539:	r7 = *(u64 *)(r10 - 312)
     540:	*(u32 *)(r10 - 84) = r6
     541:	r1 = 0
     542:	*(u32 *)(r10 - 80) = r1
     543:	r4 = r10
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     544:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     545:	r1 = r8
     546:	r2 = 0 ll
     548:	r3 = 4294967295 ll
     550:	r5 = 20
     551:	call 25
; return !entry->rx_closing || !entry->tx_closing;
     552:	r1 = *(u16 *)(r7 + 36)
     553:	r2 = r1
     554:	r2 &= 3
; if (ct_entry_alive(entry)) {
     555:	if r2 == 3 goto +40 <LBB13_81>
     556:	r6 = 60
; if (tcp) {
     557:	r2 = *(u64 *)(r10 - 256)
     558:	if r2 != 6 goto +16 <LBB13_78>
; entry->seen_non_syn |= !syn;
     559:	r2 = *(u64 *)(r10 - 328)
     560:	r2 ^= 1
     561:	r2 &= 255
     562:	r3 = r1
     563:	r3 >>= 4
     564:	r3 |= r2
     565:	r2 = r3
     566:	r2 <<= 4
     567:	r2 &= 16
     568:	r1 &= 65519
     569:	r2 |= r1
     570:	*(u16 *)(r7 + 36) = r2
; if (entry->seen_non_syn)
     571:	r3 &= 1
     572:	r6 = 60
     573:	if r3 == 0 goto +1 <LBB13_78>
     574:	r6 = 21600

LBB13_78:
; return ktime_get_ns();
     575:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     576:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
     577:	r6 += r0
     578:	*(u32 *)(r7 + 32) = r6
; seen_flags |= *accumulated_flags;
     579:	r2 = *(u8 *)(r7 + 42)
     580:	r1 = r2
     581:	r3 = *(u64 *)(r10 - 320)
     582:	r1 |= r3
     583:	r3 = r1
     584:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
     585:	if r2 != r3 goto +8 <LBB13_80>
     586:	r2 = *(u32 *)(r7 + 48)
     587:	r2 += 5
     588:	r3 = r0
     589:	r3 <<= 32
     590:	r3 >>= 32
     591:	r2 <<= 32
     592:	r2 >>= 32
     593:	if r2 >= r3 goto +2 <LBB13_81>

LBB13_80:
; *accumulated_flags = seen_flags;
     594:	*(u8 *)(r7 + 42) = r1
; *last_report = now;
     595:	*(u32 *)(r7 + 48) = r0

LBB13_81:
; ct_state->slave = entry->slave;
     596:	r1 = *(u16 *)(r7 + 40)
; ct_state->rev_nat_index = entry->rev_nat_index;
     597:	*(u64 *)(r10 - 248) = r1
     598:	r1 = *(u16 *)(r7 + 38)
; ct_state->loopback = entry->lb_loopback;
     599:	*(u64 *)(r10 - 264) = r1
     600:	r9 = *(u16 *)(r7 + 36)
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
     601:	r1 = r9
     602:	r1 &= 4
     603:	if r1 == 0 goto +4 <LBB13_84>
     604:	r1 = *(u32 *)(r8 + 60)
     605:	if r1 != 0 goto +2 <LBB13_84>
; skb->cb[CB_NAT46_STATE] = NAT46;
     606:	r1 = 2
     607:	*(u32 *)(r8 + 60) = r1

LBB13_84:
     608:	r9 >>= 3
; __sync_fetch_and_add(&entry->tx_packets, 1);
     609:	r1 = 1
     610:	lock *(u64 *)(r7 + 16) += r1
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
     611:	r1 = *(u32 *)(r8 + 0)
     612:	lock *(u64 *)(r7 + 24) += r1
     613:	r6 = *(u64 *)(r10 - 200)
     614:	r1 = *(u64 *)(r10 - 288)
; switch (action) {
     615:	if r1 == 2 goto +186 <LBB13_114>
     616:	r1 <<= 32
     617:	r1 >>= 32
     618:	if r1 != 1 goto +210 <LBB13_118>
; ret = entry->rx_closing + entry->tx_closing;
     619:	r1 = *(u16 *)(r7 + 36)
     620:	r2 = r1
     621:	r2 &= 1
     622:	r3 = r1
     623:	r3 >>= 1
     624:	r3 &= 1
; if (unlikely(ret >= 1)) {
     625:	r3 = -r3
     626:	if r2 == r3 goto +202 <LBB13_118>
     627:	r3 = r7
     628:	r7 = *(u64 *)(r10 - 248)
; entry->tx_closing = 0;
     629:	r2 = r1
     630:	r2 &= 65532
     631:	*(u16 *)(r3 + 36) = r2
     632:	r6 = 60
; if (tcp) {
     633:	r2 = *(u64 *)(r10 - 256)
     634:	if r2 != 6 goto +17 <LBB13_90>
     635:	r3 = *(u64 *)(r10 - 328)
; entry->seen_non_syn |= !syn;
     636:	r3 ^= 1
     637:	r3 &= 255
     638:	r2 = r1
     639:	r2 >>= 4
     640:	r2 |= r3
     641:	r3 = r2
     642:	r3 <<= 4
     643:	r3 &= 16
     644:	r1 &= 65516
     645:	r3 |= r1
     646:	r1 = *(u64 *)(r10 - 312)
     647:	*(u16 *)(r1 + 36) = r3
; if (entry->seen_non_syn)
     648:	r2 &= 1
     649:	r6 = 60
     650:	if r2 == 0 goto +1 <LBB13_90>
     651:	r6 = 21600

LBB13_90:
; return ktime_get_ns();
     652:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     653:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
     654:	r6 += r0
     655:	r4 = *(u64 *)(r10 - 312)
     656:	*(u32 *)(r4 + 32) = r6
; seen_flags |= *accumulated_flags;
     657:	r2 = *(u8 *)(r4 + 42)
     658:	r1 = r2
     659:	r3 = *(u64 *)(r10 - 320)
     660:	r1 |= r3
     661:	r3 = r1
     662:	r3 &= 255
     663:	r6 = *(u64 *)(r10 - 200)
; if (*last_report + CT_REPORT_INTERVAL < now ||
     664:	if r2 != r3 goto +8 <LBB13_92>
     665:	r2 = *(u32 *)(r4 + 48)
     666:	r2 += 5
     667:	r3 = r0
     668:	r3 <<= 32
     669:	r3 >>= 32
     670:	r2 <<= 32
     671:	r2 >>= 32
     672:	if r2 >= r3 goto +156 <LBB13_118>

LBB13_92:
; *accumulated_flags = seen_flags;
     673:	*(u8 *)(r4 + 42) = r1
; *last_report = now;
     674:	*(u32 *)(r4 + 48) = r0
     675:	goto +153 <LBB13_118>

LBB13_93:
     676:	r1 = 0
     677:	*(u64 *)(r10 - 256) = r1
     678:	r2 = 0
     679:	r1 = 0
; switch(ret) {
     680:	*(u64 *)(r10 - 264) = r1

LBB13_94:
     681:	*(u64 *)(r10 - 248) = r2
; tuple->flags = flags;
     682:	r1 = *(u64 *)(r10 - 200)
     683:	*(u8 *)(r1 + 37) = r9

LBB13_95:
     684:	r9 = 4294967138 ll

LBB13_96:
; if (IS_ERR(ret))
     686:	r1 = r9
     687:	r1 <<= 32
     688:	r1 >>= 32
     689:	r2 = 1
     690:	if r1 == 2 goto +1 <LBB13_98>
     691:	r2 = 0

LBB13_98:
     692:	r1 >>= 31
     693:	r1 |= r2
     694:	r6 = *(u64 *)(r10 - 200)
     695:	if r1 != 0 goto -511 <LBB13_37>

LBB13_99:
; dst->p4 = src->p4;
     696:	r1 = *(u32 *)(r6 + 12)
; dst->p3 = src->p3;
     697:	*(u64 *)(r10 - 240) = r1
     698:	r2 = *(u32 *)(r6 + 8)
; dst->p2 = src->p2;
     699:	r1 = *(u32 *)(r6 + 4)
; dst->p1 = src->p1;
     700:	*(u64 *)(r10 - 296) = r1
     701:	r1 = *(u32 *)(r6 + 0)
; if (tuple->nexthdr == IPPROTO_TCP) {
     702:	*(u64 *)(r10 - 288) = r1
     703:	r3 = *(u8 *)(r6 + 36)
; union tcp_flags tcp_flags = { 0 };
     704:	r1 = 0
     705:	*(u16 *)(r10 - 136) = r1
; tuple->flags = TUPLE_F_IN;
     706:	r1 = 1
     707:	*(u8 *)(r6 + 37) = r1
; ret = ct_lookup6(get_ct_map6(tuple), tuple, skb, l4_off, CT_EGRESS,
     708:	r7 = 0 ll
     710:	if r3 == 6 goto +2 <LBB13_101>
     711:	r7 = 0 ll

LBB13_101:
     713:	r1 = *(u64 *)(r10 - 224)
     714:	*(u64 *)(r10 - 280) = r2
; switch (tuple->nexthdr) {
     715:	*(u64 *)(r10 - 312) = r3
     716:	if r3 == 6 goto +37 <LBB13_109>
     717:	if r3 == 17 goto +309 <LBB13_135>
     718:	r9 = 4294967159 ll
     720:	if r3 != 58 goto -536 <LBB13_37>
     721:	r3 = r10
; __u8 type;
     722:	r3 += -96
     723:	r1 = 1
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     724:	*(u64 *)(r10 - 328) = r1
     725:	r1 = r8
     726:	r2 = *(u64 *)(r10 - 232)
     727:	r4 = 1
     728:	call 26
     729:	r0 <<= 32
     730:	r0 s>>= 32
     731:	if r0 s< 0 goto +51 <LBB13_111>
     732:	r1 = 0
; tuple->dport = 0;
     733:	*(u8 *)(r6 + 33) = r1
     734:	*(u8 *)(r6 + 32) = r1
; tuple->sport = 0;
     735:	*(u8 *)(r6 + 35) = r1
     736:	*(u8 *)(r6 + 34) = r1
; tuple->dport = 0;
     737:	r3 = r6
     738:	r3 += 32
     739:	r1 = *(u8 *)(r10 - 96)
; switch (type) {
     740:	r2 = r1
     741:	r2 += -1
     742:	if r2 < 4 goto +43 <LBB13_112>
     743:	if r1 == 128 goto +277 <LBB13_133>
     744:	if r1 == 129 goto +1 <LBB13_108>
     745:	goto +279 <LBB13_134>

LBB13_108:
; tuple->dport = ICMPV6_ECHO_REQUEST;
     746:	r1 = 128
     747:	*(u8 *)(r3 + 0) = r1
     748:	r2 = 0
     749:	r1 = 0
     750:	*(u64 *)(r10 - 328) = r1
     751:	*(u8 *)(r3 + 1) = r2
     752:	*(u64 *)(r10 - 336) = r3
     753:	goto +287 <LBB13_136>

LBB13_109:
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     754:	r2 = r1
     755:	r2 += 26
     756:	r3 = r10
     757:	r3 += -136
     758:	r1 = r8
     759:	r4 = 2
     760:	call 26
     761:	r9 = 4294967161 ll
     763:	r0 <<= 32
     764:	r0 s>>= 32
     765:	if r0 s< 0 goto -581 <LBB13_37>
     766:	*(u64 *)(r10 - 320) = r7
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     767:	r7 = *(u8 *)(r10 - 136)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     768:	r3 = r6
     769:	r3 += 32
     770:	r1 = r8
     771:	r2 = *(u64 *)(r10 - 232)
     772:	*(u64 *)(r10 - 336) = r3
     773:	r4 = 4
     774:	call 26
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     775:	r7 &= 1
     776:	r7 += 1
     777:	*(u64 *)(r10 - 328) = r7
     778:	r7 = *(u64 *)(r10 - 320)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     779:	r0 <<= 32
     780:	r0 s>>= 32
     781:	if r0 s< 0 goto -597 <LBB13_37>
     782:	goto +258 <LBB13_136>

LBB13_111:
     783:	r9 = 4294967161 ll
     785:	goto -601 <LBB13_37>

LBB13_112:
; tuple->flags |= TUPLE_F_RELATED;
     786:	r1 = *(u8 *)(r6 + 37)
     787:	r1 |= 2
     788:	*(u8 *)(r6 + 37) = r1
     789:	r1 = 0
; break;
     790:	*(u64 *)(r10 - 328) = r1
     791:	*(u64 *)(r10 - 336) = r3
     792:	goto +248 <LBB13_136>

LBB13_113:
     793:	r1 = 0
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
     794:	*(u64 *)(r10 - 256) = r1
     795:	r1 = 0
     796:	*(u32 *)(r8 + 60) = r1
     797:	r1 = 0
     798:	*(u64 *)(r10 - 248) = r1
     799:	r9 = 0
     800:	r6 = 0
     801:	goto +34 <LBB13_119>

LBB13_114:
     802:	r1 = *(u16 *)(r7 + 36)
; if (dir == CT_INGRESS)
     803:	r1 |= 2
     804:	*(u16 *)(r7 + 36) = r1
; return !entry->rx_closing || !entry->tx_closing;
     805:	r1 &= 3
; if (ct_entry_alive(entry))
     806:	if r1 != 3 goto +22 <LBB13_118>
; return ktime_get_ns();
     807:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     808:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
     809:	r1 = r0
     810:	r1 += 10
     811:	*(u32 *)(r7 + 32) = r1
; seen_flags |= *accumulated_flags;
     812:	r2 = *(u8 *)(r7 + 42)
     813:	r1 = r2
     814:	r3 = *(u64 *)(r10 - 320)
     815:	r1 |= r3
     816:	r3 = r1
     817:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
     818:	if r2 != r3 goto +8 <LBB13_117>
     819:	r2 = *(u32 *)(r7 + 48)
     820:	r2 += 5
     821:	r3 = r0
     822:	r3 <<= 32
     823:	r3 >>= 32
     824:	r2 <<= 32
     825:	r2 >>= 32
     826:	if r2 >= r3 goto +2 <LBB13_118>

LBB13_117:
; *accumulated_flags = seen_flags;
     827:	*(u8 *)(r7 + 42) = r1
; *last_report = now;
     828:	*(u32 *)(r7 + 48) = r0

LBB13_118:
     829:	r9 &= 1
     830:	*(u64 *)(r10 - 256) = r9
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
     831:	r6 = *(u8 *)(r6 + 37)
     832:	r6 >>= 1
     833:	r6 &= 1
     834:	r6 |= 2
     835:	r9 = *(u64 *)(r10 - 264)

LBB13_119:
; uint32_t hash = get_hash_recalc(skb);
     836:	r1 = r8
     837:	call 34
; struct debug_msg msg = {
     838:	*(u32 *)(r10 - 92) = r0
     839:	r1 = 269487874
     840:	*(u32 *)(r10 - 96) = r1
     841:	r7 = 0
     842:	*(u32 *)(r10 - 80) = r7
     843:	*(u32 *)(r10 - 88) = r6
     844:	*(u64 *)(r10 - 264) = r9
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
     845:	r9 &= 65535
; struct debug_msg msg = {
     846:	*(u32 *)(r10 - 84) = r9
     847:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
     848:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     849:	r1 = r8
     850:	r2 = 0 ll
     852:	r3 = 4294967295 ll
     854:	r5 = 20
     855:	call 25
     856:	r6 &= 255
; switch(ret) {
     857:	r1 = r6
     858:	r1 += -1
     859:	if r1 < 3 goto +3858 <LBB13_466>
     860:	*(u64 *)(r10 - 288) = r9
     861:	r1 = *(u64 *)(r10 - 256)
     862:	*(u64 *)(r10 - 256) = r1
     863:	r9 = *(u64 *)(r10 - 296)
     864:	r2 = *(u64 *)(r10 - 248)
     865:	if r6 == 0 goto +1 <LBB13_121>
     866:	goto -186 <LBB13_94>

LBB13_121:
     867:	r1 = *(u64 *)(r10 - 280)
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     868:	r7 = *(u8 *)(r1 + 22)
     869:	r6 = *(u8 *)(r1 + 23)
     870:	r2 = *(u8 *)(r1 + 18)
     871:	*(u64 *)(r10 - 312) = r2
     872:	r1 = *(u8 *)(r1 + 19)
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     873:	*(u64 *)(r10 - 248) = r1
     874:	r9 = r10
; struct lb6_service *svc;
     875:	r9 += -96
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     876:	r1 = r8
     877:	r2 = 0
     878:	r3 = r9
     879:	r4 = 4
     880:	call 26
; skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
     881:	r1 = r8
     882:	r2 = 0
     883:	r3 = r9
     884:	r4 = 4
     885:	r5 = 2
     886:	call 9
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     887:	r6 <<= 8
     888:	r6 |= r7
; return get_hash_recalc(skb);
     889:	r1 = r8
     890:	call 34
     891:	r7 = r0
; if (weight) {
     892:	if r6 == 0 goto +29 <LBB13_126>
     893:	r2 = r10
; struct lb6_key *key,
     894:	r2 += -168
; seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
     895:	r1 = 0 ll
     897:	call 1
; if (seq && seq->count != 0)
     898:	if r0 == 0 goto +23 <LBB13_126>
     899:	r1 = *(u16 *)(r0 + 0)
     900:	if r1 == 0 goto +21 <LBB13_126>
; slave = lb_next_rr(skb, seq, hash);
     901:	r6 = r7
     902:	r6 &= 65535
; __u8 offset = hash % seq->count;
     903:	r2 = r6
     904:	r2 /= r1
     905:	r2 *= r1
     906:	r1 = r6
     907:	r1 -= r2
; if (offset < LB_RR_MAX_SEQ) {
     908:	r1 &= 255
     909:	if r1 > 30 goto +12 <LBB13_126>
; slave = seq->idx[offset] + 1;
     910:	r1 <<= 1
     911:	r0 += r1
     912:	r7 = *(u16 *)(r0 + 2)
; uint32_t hash = get_hash_recalc(skb);
     913:	r1 = r8
     914:	call 34
; struct debug_msg msg = {
     915:	*(u32 *)(r10 - 92) = r0
     916:	r1 = 269493506
     917:	*(u32 *)(r10 - 96) = r1
     918:	*(u32 *)(r10 - 88) = r6
     919:	r1 = 0
     920:	*(u32 *)(r10 - 80) = r1
     921:	goto +18 <LBB13_127>

LBB13_126:
     922:	r6 = *(u64 *)(r10 - 248)
     923:	r6 <<= 8
     924:	r1 = *(u64 *)(r10 - 312)
     925:	r6 |= r1
; uint32_t hash = get_hash_recalc(skb);
     926:	r1 = r8
     927:	call 34
; struct debug_msg msg = {
     928:	*(u32 *)(r10 - 92) = r0
     929:	r1 = 269489410
     930:	*(u32 *)(r10 - 96) = r1
     931:	r1 = 0
     932:	*(u32 *)(r10 - 80) = r1
     933:	*(u32 *)(r10 - 88) = r7
; slave = (hash % count) + 1;
     934:	r7 <<= 32
     935:	r7 >>= 32
     936:	r1 = r7
     937:	r1 /= r6
     938:	r1 *= r6
     939:	r7 -= r1

LBB13_127:
     940:	r7 += 1
; struct debug_msg msg = {
     941:	*(u32 *)(r10 - 84) = r7
     942:	r4 = r10
     943:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     944:	r1 = r8
     945:	r2 = 0 ll
     947:	r3 = 4294967295 ll
     949:	r5 = 20
     950:	call 25
     951:	r3 = *(u64 *)(r10 - 256)
     952:	r6 = *(u64 *)(r10 - 288)
     953:	r1 = 0
; struct ct_entry entry = { };
     954:	*(u64 *)(r10 - 48) = r1
     955:	*(u64 *)(r10 - 56) = r1
     956:	*(u64 *)(r10 - 64) = r1
     957:	*(u64 *)(r10 - 72) = r1
     958:	*(u64 *)(r10 - 80) = r1
     959:	*(u64 *)(r10 - 88) = r1
     960:	*(u64 *)(r10 - 96) = r1
; bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
     961:	r1 = *(u64 *)(r10 - 200)
     962:	r2 = *(u8 *)(r1 + 36)
; entry.rev_nat_index = ct_state->rev_nat_index;
     963:	r1 = *(u64 *)(r10 - 264)
     964:	*(u16 *)(r10 - 58) = r1
; entry.slave = ct_state->slave;
     965:	*(u16 *)(r10 - 56) = r7
; entry.lb_loopback = ct_state->loopback;
     966:	r1 = r3
     967:	r1 <<= 3
     968:	*(u16 *)(r10 - 60) = r1
; if (tcp) {
     969:	if r2 != 6 goto +1 <LBB13_129>
; entry->seen_non_syn |= !syn;
     970:	*(u16 *)(r10 - 60) = r1

LBB13_129:
     971:	*(u64 *)(r10 - 248) = r7
; return ktime_get_ns();
     972:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     973:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
     974:	r1 = r0
     975:	r1 += 60
     976:	*(u32 *)(r10 - 64) = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     977:	r1 = r0
     978:	r1 <<= 32
     979:	r1 >>= 32
; if (*last_report + CT_REPORT_INTERVAL < now ||
     980:	r2 = *(u32 *)(r10 - 48)
     981:	r2 += 5
     982:	r2 <<= 32
     983:	r2 >>= 32
     984:	if r2 >= r1 goto +1 <LBB13_131>
; *last_report = now;
     985:	*(u32 *)(r10 - 48) = r0

LBB13_131:
     986:	r1 = 1
; entry.tx_packets = 1;
     987:	*(u64 *)(r10 - 80) = r1
; entry.tx_bytes = skb->len;
     988:	r1 = *(u32 *)(r8 + 0)
     989:	*(u64 *)(r10 - 72) = r1
; uint32_t hash = get_hash_recalc(skb);
     990:	r1 = r8
     991:	call 34
; struct debug_msg msg = {
     992:	*(u32 *)(r10 - 132) = r0
     993:	r1 = 269496578
     994:	*(u32 *)(r10 - 136) = r1
     995:	*(u32 *)(r10 - 128) = r6
     996:	r6 = 0
     997:	*(u32 *)(r10 - 124) = r6
     998:	*(u32 *)(r10 - 120) = r6
     999:	r4 = r10
; entry.tx_packets = 1;
    1000:	r4 += -136
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1001:	r1 = r8
    1002:	r2 = 0 ll
    1004:	r3 = 4294967295 ll
    1006:	r5 = 20
    1007:	call 25
; entry.src_sec_id = ct_state->src_sec_id;
    1008:	*(u32 *)(r10 - 52) = r6
    1009:	r3 = r10
; entry.tx_packets = 1;
    1010:	r3 += -96
    1011:	r9 = *(u64 *)(r10 - 240)
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    1012:	r1 = r9
    1013:	r7 = *(u64 *)(r10 - 200)
    1014:	r2 = r7
    1015:	r4 = 0
    1016:	call 2
    1017:	r0 <<= 32
    1018:	r0 s>>= 32
    1019:	if r0 s> -1 goto +3657 <LBB13_464>
    1020:	goto +3693 <LBB13_465>

LBB13_133:
; tuple->sport = type;
    1021:	r1 = 0
    1022:	*(u8 *)(r6 + 35) = r1
    1023:	r1 = 128
    1024:	*(u8 *)(r6 + 34) = r1

LBB13_134:
    1025:	*(u64 *)(r10 - 336) = r3
    1026:	goto +14 <LBB13_136>

LBB13_135:
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
    1027:	r3 = r6
    1028:	r3 += 32
    1029:	r1 = r8
    1030:	r2 = *(u64 *)(r10 - 232)
    1031:	*(u64 *)(r10 - 336) = r3
    1032:	r4 = 4
    1033:	call 26
    1034:	r1 = 1
    1035:	*(u64 *)(r10 - 328) = r1
    1036:	r9 = 4294967161 ll
    1038:	r0 <<= 32
    1039:	r0 s>>= 32
    1040:	if r0 s< 0 goto -856 <LBB13_37>

LBB13_136:
    1041:	*(u64 *)(r10 - 320) = r7
    1042:	r1 = *(u64 *)(r10 - 240)
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1043:	r1 = *(u8 *)(r6 + 29)
    1044:	r1 <<= 8
    1045:	r2 = *(u8 *)(r6 + 28)
    1046:	r1 |= r2
    1047:	r9 = *(u8 *)(r6 + 31)
    1048:	r9 <<= 8
    1049:	r2 = *(u8 *)(r6 + 30)
    1050:	r9 |= r2
    1051:	r2 = *(u8 *)(r6 + 13)
    1052:	r2 <<= 8
    1053:	r3 = *(u8 *)(r6 + 12)
    1054:	r2 |= r3
    1055:	r7 = *(u8 *)(r6 + 15)
    1056:	r7 <<= 8
    1057:	r3 = *(u8 *)(r6 + 14)
    1058:	r7 |= r3
    1059:	r7 <<= 16
    1060:	r7 |= r2
    1061:	r9 <<= 16
    1062:	r9 |= r1
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1063:	r1 = *(u64 *)(r10 - 200)
    1064:	r6 = *(u8 *)(r1 + 35)
    1065:	r6 <<= 8
    1066:	r1 = *(u64 *)(r10 - 200)
    1067:	r1 = *(u8 *)(r1 + 34)
    1068:	r6 |= r1
    1069:	r1 = *(u64 *)(r10 - 200)
    1070:	r1 = *(u8 *)(r1 + 32)
    1071:	*(u64 *)(r10 - 344) = r1
    1072:	*(u64 *)(r10 - 216) = r8
    1073:	r1 = *(u64 *)(r10 - 200)
    1074:	r8 = *(u8 *)(r1 + 33)
; uint32_t hash = get_hash_recalc(skb);
    1075:	r1 = *(u64 *)(r10 - 216)
    1076:	call 34
; struct debug_msg msg = {
    1077:	*(u32 *)(r10 - 92) = r0
    1078:	r1 = 269496066
    1079:	*(u32 *)(r10 - 96) = r1
    1080:	*(u32 *)(r10 - 88) = r9
    1081:	*(u32 *)(r10 - 84) = r7
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1082:	r6 = be32 r6
    1083:	r1 = 4294901760 ll
    1085:	r6 &= r1
    1086:	r8 <<= 8
    1087:	r1 = *(u64 *)(r10 - 344)
    1088:	r8 |= r1
    1089:	r8 = be16 r8
    1090:	r6 |= r8
    1091:	r8 = *(u64 *)(r10 - 216)
; struct debug_msg msg = {
    1092:	*(u32 *)(r10 - 80) = r6
    1093:	r4 = r10
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1094:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1095:	r1 = r8
    1096:	r2 = 0 ll
    1098:	r3 = 4294967295 ll
    1100:	r5 = 20
    1101:	call 25
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1102:	r1 = *(u64 *)(r10 - 200)
    1103:	r6 = *(u8 *)(r1 + 37)
    1104:	r1 = *(u64 *)(r10 - 200)
    1105:	r7 = *(u8 *)(r1 + 36)
; uint32_t hash = get_hash_recalc(skb);
    1106:	r1 = r8
    1107:	call 34
; struct debug_msg msg = {
    1108:	*(u32 *)(r10 - 92) = r0
    1109:	r1 = 269496322
    1110:	*(u32 *)(r10 - 96) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1111:	r7 <<= 8
    1112:	r7 |= r6
    1113:	r6 = *(u64 *)(r10 - 200)
; struct debug_msg msg = {
    1114:	*(u32 *)(r10 - 88) = r7
    1115:	r7 = *(u64 *)(r10 - 320)
    1116:	r1 = 0
    1117:	*(u32 *)(r10 - 84) = r1
    1118:	*(u32 *)(r10 - 80) = r1
    1119:	r4 = r10
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1120:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1121:	r1 = r8
    1122:	r2 = 0 ll
    1124:	r3 = 4294967295 ll
    1126:	r5 = 20
    1127:	call 25
    1128:	r1 = *(u8 *)(r10 - 135)
    1129:	*(u64 *)(r10 - 344) = r1
    1130:	r1 = *(u8 *)(r10 - 136)
; if ((entry = map_lookup_elem(map, tuple))) {
    1131:	*(u64 *)(r10 - 352) = r1
    1132:	r1 = r7
    1133:	r2 = r6
    1134:	call 1
    1135:	r9 = r0
    1136:	if r9 == 0 goto +147 <LBB13_156>
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1137:	r6 = *(u16 *)(r9 + 38)
    1138:	r8 = *(u64 *)(r10 - 216)
    1139:	r7 = *(u32 *)(r9 + 32)
; uint32_t hash = get_hash_recalc(skb);
    1140:	r1 = r8
    1141:	call 34
; struct debug_msg msg = {
    1142:	*(u32 *)(r10 - 92) = r0
    1143:	r1 = 269486082
    1144:	*(u32 *)(r10 - 96) = r1
    1145:	*(u32 *)(r10 - 88) = r7
    1146:	*(u32 *)(r10 - 84) = r6
    1147:	r7 = 0
    1148:	r1 = 0
    1149:	*(u32 *)(r10 - 80) = r1
    1150:	r4 = r10
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1151:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1152:	r1 = r8
    1153:	r2 = 0 ll
    1155:	r3 = 4294967295 ll
    1157:	r5 = 20
    1158:	call 25
; return !entry->rx_closing || !entry->tx_closing;
    1159:	r1 = *(u16 *)(r9 + 36)
    1160:	r2 = r1
    1161:	r2 &= 3
    1162:	r3 = *(u64 *)(r10 - 208)
; if (ct_entry_alive(entry)) {
    1163:	if r2 == 3 goto +41 <LBB13_144>
    1164:	r6 = 60
; if (tcp) {
    1165:	r2 = *(u64 *)(r10 - 312)
    1166:	if r2 != 6 goto +16 <LBB13_141>
; entry->seen_non_syn |= !syn;
    1167:	r2 = *(u64 *)(r10 - 352)
    1168:	r2 ^= 1
    1169:	r2 &= 255
    1170:	r3 = r1
    1171:	r3 >>= 4
    1172:	r3 |= r2
    1173:	r2 = r3
    1174:	r2 <<= 4
    1175:	r2 &= 16
    1176:	r1 &= 65519
    1177:	r2 |= r1
    1178:	*(u16 *)(r9 + 36) = r2
; if (entry->seen_non_syn)
    1179:	r3 &= 1
    1180:	r6 = 60
    1181:	if r3 == 0 goto +1 <LBB13_141>
    1182:	r6 = 21600

LBB13_141:
; return ktime_get_ns();
    1183:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1184:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1185:	r6 += r0
    1186:	*(u32 *)(r9 + 32) = r6
; seen_flags |= *accumulated_flags;
    1187:	r2 = *(u8 *)(r9 + 42)
    1188:	r1 = r2
    1189:	r3 = *(u64 *)(r10 - 344)
    1190:	r1 |= r3
    1191:	r3 = r1
    1192:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1193:	if r2 != r3 goto +8 <LBB13_143>
    1194:	r2 = *(u32 *)(r9 + 48)
    1195:	r2 += 5
    1196:	r3 = r0
    1197:	r3 <<= 32
    1198:	r3 >>= 32
    1199:	r2 <<= 32
    1200:	r2 >>= 32
    1201:	if r2 >= r3 goto +3 <LBB13_144>

LBB13_143:
; *accumulated_flags = seen_flags;
    1202:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1203:	*(u32 *)(r9 + 48) = r0
    1204:	r7 = 128

LBB13_144:
; ct_state->rev_nat_index = entry->rev_nat_index;
    1205:	r1 = *(u16 *)(r9 + 38)
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1206:	*(u64 *)(r10 - 320) = r1
    1207:	r1 = *(u8 *)(r9 + 36)
    1208:	r1 &= 4
    1209:	if r1 == 0 goto +6 <LBB13_147>
    1210:	r1 = *(u64 *)(r10 - 216)
    1211:	r1 = *(u32 *)(r1 + 60)
    1212:	if r1 != 0 goto +3 <LBB13_147>
; skb->cb[CB_NAT46_STATE] = NAT46;
    1213:	r1 = 2
    1214:	r2 = *(u64 *)(r10 - 216)
    1215:	*(u32 *)(r2 + 60) = r1

LBB13_147:
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1216:	r1 = 1
    1217:	lock *(u64 *)(r9 + 16) += r1
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1218:	r1 = *(u64 *)(r10 - 216)
    1219:	r1 = *(u32 *)(r1 + 0)
    1220:	lock *(u64 *)(r9 + 24) += r1
    1221:	r6 = *(u64 *)(r10 - 200)
    1222:	r1 = *(u64 *)(r10 - 328)
; switch (action) {
    1223:	if r1 == 2 goto +258 <LBB13_178>
    1224:	r1 <<= 32
    1225:	r1 >>= 32
    1226:	if r1 != 1 goto +283 <LBB13_182>
; ret = entry->rx_closing + entry->tx_closing;
    1227:	r1 = *(u16 *)(r9 + 36)
    1228:	r2 = r1
    1229:	r2 &= 1
    1230:	r3 = r1
    1231:	r3 >>= 1
    1232:	r3 &= 1
; if (unlikely(ret >= 1)) {
    1233:	r3 = -r3
    1234:	if r2 == r3 goto +275 <LBB13_182>
; entry->tx_closing = 0;
    1235:	r2 = r1
    1236:	r2 &= 65532
    1237:	*(u16 *)(r9 + 36) = r2
    1238:	r6 = 60
; if (tcp) {
    1239:	r2 = *(u64 *)(r10 - 312)
    1240:	if r2 != 6 goto +16 <LBB13_153>
    1241:	r3 = *(u64 *)(r10 - 352)
; entry->seen_non_syn |= !syn;
    1242:	r3 ^= 1
    1243:	r3 &= 255
    1244:	r2 = r1
    1245:	r2 >>= 4
    1246:	r2 |= r3
    1247:	r3 = r2
    1248:	r3 <<= 4
    1249:	r3 &= 16
    1250:	r1 &= 65516
    1251:	r3 |= r1
    1252:	*(u16 *)(r9 + 36) = r3
; if (entry->seen_non_syn)
    1253:	r2 &= 1
    1254:	r6 = 60
    1255:	if r2 == 0 goto +1 <LBB13_153>
    1256:	r6 = 21600

LBB13_153:
; return ktime_get_ns();
    1257:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1258:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1259:	r6 += r0
    1260:	*(u32 *)(r9 + 32) = r6
; seen_flags |= *accumulated_flags;
    1261:	r2 = *(u8 *)(r9 + 42)
    1262:	r1 = r2
    1263:	r3 = *(u64 *)(r10 - 344)
    1264:	r1 |= r3
    1265:	r3 = r1
    1266:	r3 &= 255
    1267:	r4 = *(u64 *)(r10 - 216)
    1268:	r4 = *(u64 *)(r10 - 208)
    1269:	r6 = *(u64 *)(r10 - 200)
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1270:	if r2 != r3 goto +9 <LBB13_155>
    1271:	r7 = 0
    1272:	r2 = *(u32 *)(r9 + 48)
    1273:	r2 += 5
    1274:	r3 = r0
    1275:	r3 <<= 32
    1276:	r3 >>= 32
    1277:	r2 <<= 32
    1278:	r2 >>= 32
    1279:	if r2 >= r3 goto +230 <LBB13_182>

LBB13_155:
; *accumulated_flags = seen_flags;
    1280:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1281:	*(u32 *)(r9 + 48) = r0
    1282:	r7 = 128
    1283:	goto +226 <LBB13_182>

LBB13_156:
; tmp = tuple->sport;
    1284:	r1 = *(u8 *)(r6 + 35)
; tuple->sport = tuple->dport;
    1285:	r2 = *(u8 *)(r6 + 33)
    1286:	*(u8 *)(r6 + 35) = r2
; tmp = tuple->sport;
    1287:	r2 = *(u8 *)(r6 + 34)
; tuple->sport = tuple->dport;
    1288:	r3 = *(u8 *)(r6 + 32)
    1289:	*(u8 *)(r6 + 34) = r3
; dst->p1 = src->p1;
    1290:	r3 = *(u32 *)(r6 + 16)
    1291:	r4 = *(u32 *)(r6 + 0)
    1292:	*(u32 *)(r6 + 16) = r4
; dst->p2 = src->p2;
    1293:	r4 = *(u32 *)(r6 + 4)
    1294:	r5 = *(u32 *)(r6 + 20)
    1295:	*(u32 *)(r6 + 4) = r5
    1296:	*(u32 *)(r6 + 20) = r4
; dst->p3 = src->p3;
    1297:	r4 = *(u32 *)(r6 + 8)
    1298:	r5 = *(u32 *)(r6 + 24)
    1299:	*(u32 *)(r6 + 8) = r5
    1300:	*(u32 *)(r6 + 24) = r4
; dst->p4 = src->p4;
    1301:	r4 = *(u32 *)(r6 + 12)
    1302:	r5 = *(u32 *)(r6 + 28)
    1303:	*(u32 *)(r6 + 12) = r5
    1304:	*(u32 *)(r6 + 28) = r4
; dst->p1 = src->p1;
    1305:	*(u32 *)(r6 + 0) = r3
; tuple->dport = tmp;
    1306:	*(u8 *)(r6 + 33) = r1
    1307:	*(u8 *)(r6 + 32) = r2
; if (tuple->flags & TUPLE_F_IN)
    1308:	r1 = *(u8 *)(r6 + 37)
; tuple->flags |= TUPLE_F_IN;
    1309:	r2 = r1
    1310:	r2 |= 1
; if (tuple->flags & TUPLE_F_IN)
    1311:	r3 = r1
    1312:	r3 &= 1
    1313:	if r3 == 0 goto +2 <LBB13_158>
    1314:	r1 &= 254
    1315:	r2 = r1

LBB13_158:
    1316:	*(u8 *)(r6 + 37) = r2
    1317:	r1 = *(u8 *)(r10 - 135)
    1318:	*(u64 *)(r10 - 344) = r1
    1319:	r1 = *(u8 *)(r10 - 136)
; if ((entry = map_lookup_elem(map, tuple))) {
    1320:	*(u64 *)(r10 - 352) = r1
    1321:	r1 = r7
    1322:	r2 = r6
    1323:	call 1
    1324:	r9 = r0
    1325:	r7 = 128
    1326:	r4 = 0
    1327:	r1 = 0
    1328:	*(u64 *)(r10 - 320) = r1
    1329:	r6 = 0
    1330:	r1 = *(u64 *)(r10 - 208)
    1331:	if r9 == 0 goto +212 <LBB13_187>
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1332:	r6 = *(u16 *)(r9 + 38)
    1333:	r7 = *(u32 *)(r9 + 32)
    1334:	r8 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    1335:	r1 = r8
    1336:	call 34
; struct debug_msg msg = {
    1337:	*(u32 *)(r10 - 92) = r0
    1338:	r1 = 269486082
    1339:	*(u32 *)(r10 - 96) = r1
    1340:	*(u32 *)(r10 - 88) = r7
    1341:	*(u32 *)(r10 - 84) = r6
    1342:	r1 = 0
    1343:	*(u32 *)(r10 - 80) = r1
    1344:	r4 = r10
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1345:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1346:	r1 = r8
    1347:	r2 = 0 ll
    1349:	r3 = 4294967295 ll
    1351:	r5 = 20
    1352:	call 25
; return !entry->rx_closing || !entry->tx_closing;
    1353:	r1 = *(u16 *)(r9 + 36)
    1354:	r2 = r1
    1355:	r2 &= 3
    1356:	r7 = 128
; if (ct_entry_alive(entry)) {
    1357:	if r2 == 3 goto +42 <LBB13_166>
    1358:	r6 = 60
; if (tcp) {
    1359:	r2 = *(u64 *)(r10 - 312)
    1360:	if r2 != 6 goto +16 <LBB13_163>
; entry->seen_non_syn |= !syn;
    1361:	r2 = *(u64 *)(r10 - 352)
    1362:	r2 ^= 1
    1363:	r2 &= 255
    1364:	r3 = r1
    1365:	r3 >>= 4
    1366:	r3 |= r2
    1367:	r2 = r3
    1368:	r2 <<= 4
    1369:	r2 &= 16
    1370:	r1 &= 65519
    1371:	r2 |= r1
    1372:	*(u16 *)(r9 + 36) = r2
; if (entry->seen_non_syn)
    1373:	r3 &= 1
    1374:	r6 = 60
    1375:	if r3 == 0 goto +1 <LBB13_163>
    1376:	r6 = 21600

LBB13_163:
; return ktime_get_ns();
    1377:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1378:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1379:	r6 += r0
    1380:	*(u32 *)(r9 + 32) = r6
; seen_flags |= *accumulated_flags;
    1381:	r2 = *(u8 *)(r9 + 42)
    1382:	r1 = r2
    1383:	r3 = *(u64 *)(r10 - 344)
    1384:	r1 |= r3
    1385:	r3 = r1
    1386:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1387:	if r2 != r3 goto +9 <LBB13_165>
    1388:	r7 = 0
    1389:	r2 = *(u32 *)(r9 + 48)
    1390:	r2 += 5
    1391:	r3 = r0
    1392:	r3 <<= 32
    1393:	r3 >>= 32
    1394:	r2 <<= 32
    1395:	r2 >>= 32
    1396:	if r2 >= r3 goto +3 <LBB13_166>

LBB13_165:
; *accumulated_flags = seen_flags;
    1397:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1398:	*(u32 *)(r9 + 48) = r0
    1399:	r7 = 128

LBB13_166:
; ct_state->rev_nat_index = entry->rev_nat_index;
    1400:	r1 = *(u16 *)(r9 + 38)
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1401:	*(u64 *)(r10 - 320) = r1
    1402:	r1 = *(u8 *)(r9 + 36)
    1403:	r1 &= 4
    1404:	if r1 == 0 goto +6 <LBB13_169>
    1405:	r1 = *(u64 *)(r10 - 216)
    1406:	r1 = *(u32 *)(r1 + 60)
    1407:	if r1 != 0 goto +3 <LBB13_169>
; skb->cb[CB_NAT46_STATE] = NAT46;
    1408:	r1 = 2
    1409:	r2 = *(u64 *)(r10 - 216)
    1410:	*(u32 *)(r2 + 60) = r1

LBB13_169:
    1411:	r6 = 1
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1412:	r1 = 1
    1413:	lock *(u64 *)(r9 + 16) += r1
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1414:	r1 = *(u64 *)(r10 - 216)
    1415:	r1 = *(u32 *)(r1 + 0)
    1416:	lock *(u64 *)(r9 + 24) += r1
    1417:	r1 = *(u64 *)(r10 - 208)
    1418:	r1 = *(u64 *)(r10 - 328)
    1419:	r4 = 0
; switch (action) {
    1420:	if r1 == 2 goto +94 <LBB13_183>
    1421:	r1 <<= 32
    1422:	r1 >>= 32
    1423:	if r1 != 1 goto +120 <LBB13_187>
; ret = entry->rx_closing + entry->tx_closing;
    1424:	r1 = *(u16 *)(r9 + 36)
    1425:	r2 = r1
    1426:	r2 &= 1
    1427:	r3 = r1
    1428:	r3 >>= 1
    1429:	r3 &= 1
; if (unlikely(ret >= 1)) {
    1430:	r3 = -r3
    1431:	if r2 == r3 goto +112 <LBB13_187>
; entry->tx_closing = 0;
    1432:	r2 = r1
    1433:	r2 &= 65532
    1434:	*(u16 *)(r9 + 36) = r2
    1435:	r6 = 60
; if (tcp) {
    1436:	r2 = *(u64 *)(r10 - 312)
    1437:	if r2 != 6 goto +16 <LBB13_175>
    1438:	r3 = *(u64 *)(r10 - 352)
; entry->seen_non_syn |= !syn;
    1439:	r3 ^= 1
    1440:	r3 &= 255
    1441:	r2 = r1
    1442:	r2 >>= 4
    1443:	r2 |= r3
    1444:	r3 = r2
    1445:	r3 <<= 4
    1446:	r3 &= 16
    1447:	r1 &= 65516
    1448:	r3 |= r1
    1449:	*(u16 *)(r9 + 36) = r3
; if (entry->seen_non_syn)
    1450:	r2 &= 1
    1451:	r6 = 60
    1452:	if r2 == 0 goto +1 <LBB13_175>
    1453:	r6 = 21600

LBB13_175:
; return ktime_get_ns();
    1454:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1455:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1456:	r6 += r0
    1457:	*(u32 *)(r9 + 32) = r6
; seen_flags |= *accumulated_flags;
    1458:	r2 = *(u8 *)(r9 + 42)
    1459:	r1 = r2
    1460:	r3 = *(u64 *)(r10 - 344)
    1461:	r1 |= r3
    1462:	r3 = r1
    1463:	r3 &= 255
    1464:	r4 = *(u64 *)(r10 - 216)
    1465:	r4 = *(u64 *)(r10 - 208)
    1466:	r6 = 1
    1467:	r4 = 0
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1468:	if r2 != r3 goto +9 <LBB13_177>
    1469:	r7 = 0
    1470:	r2 = *(u32 *)(r9 + 48)
    1471:	r2 += 5
    1472:	r3 = r0
    1473:	r3 <<= 32
    1474:	r3 >>= 32
    1475:	r2 <<= 32
    1476:	r2 >>= 32
    1477:	if r2 >= r3 goto +66 <LBB13_187>

LBB13_177:
; *accumulated_flags = seen_flags;
    1478:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1479:	*(u32 *)(r9 + 48) = r0
    1480:	r7 = 128
    1481:	goto +62 <LBB13_187>

LBB13_178:
    1482:	r1 = *(u16 *)(r9 + 36)
; if (dir == CT_INGRESS)
    1483:	r1 |= 2
    1484:	*(u16 *)(r9 + 36) = r1
    1485:	r7 = 128
; return !entry->rx_closing || !entry->tx_closing;
    1486:	r1 &= 3
; if (ct_entry_alive(entry))
    1487:	if r1 != 3 goto +22 <LBB13_182>
; return ktime_get_ns();
    1488:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1489:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1490:	r1 = r0
    1491:	r1 += 10
    1492:	*(u32 *)(r9 + 32) = r1
; seen_flags |= *accumulated_flags;
    1493:	r2 = *(u8 *)(r9 + 42)
    1494:	r1 = r2
    1495:	r3 = *(u64 *)(r10 - 344)
    1496:	r1 |= r3
    1497:	r3 = r1
    1498:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1499:	if r2 != r3 goto +8 <LBB13_181>
    1500:	r2 = *(u32 *)(r9 + 48)
    1501:	r2 += 5
    1502:	r3 = r0
    1503:	r3 <<= 32
    1504:	r3 >>= 32
    1505:	r2 <<= 32
    1506:	r2 >>= 32
    1507:	if r2 >= r3 goto +2 <LBB13_182>

LBB13_181:
; *accumulated_flags = seen_flags;
    1508:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1509:	*(u32 *)(r9 + 48) = r0

LBB13_182:
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1510:	r6 = *(u8 *)(r6 + 37)
    1511:	r6 >>= 1
    1512:	r6 &= 1
    1513:	r6 |= 2
    1514:	goto +31 <LBB13_188>

LBB13_183:
    1515:	r1 = *(u16 *)(r9 + 36)
; if (dir == CT_INGRESS)
    1516:	r1 |= 2
    1517:	*(u16 *)(r9 + 36) = r1
    1518:	r7 = 128
; return !entry->rx_closing || !entry->tx_closing;
    1519:	r1 &= 3
; if (ct_entry_alive(entry))
    1520:	if r1 != 3 goto +23 <LBB13_187>
; return ktime_get_ns();
    1521:	call 5
    1522:	r4 = 0
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1523:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    1524:	r1 = r0
    1525:	r1 += 10
    1526:	*(u32 *)(r9 + 32) = r1
; seen_flags |= *accumulated_flags;
    1527:	r2 = *(u8 *)(r9 + 42)
    1528:	r1 = r2
    1529:	r3 = *(u64 *)(r10 - 344)
    1530:	r1 |= r3
    1531:	r3 = r1
    1532:	r3 &= 255
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1533:	if r2 != r3 goto +8 <LBB13_186>
    1534:	r2 = *(u32 *)(r9 + 48)
    1535:	r2 += 5
    1536:	r3 = r0
    1537:	r3 <<= 32
    1538:	r3 >>= 32
    1539:	r2 <<= 32
    1540:	r2 >>= 32
    1541:	if r2 >= r3 goto +2 <LBB13_187>

LBB13_186:
; *accumulated_flags = seen_flags;
    1542:	*(u8 *)(r9 + 42) = r1
; *last_report = now;
    1543:	*(u32 *)(r9 + 48) = r0

LBB13_187:
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
    1544:	r1 = *(u64 *)(r10 - 216)
    1545:	*(u32 *)(r1 + 60) = r4

LBB13_188:
    1546:	r8 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    1547:	r1 = r8
    1548:	call 34
; struct debug_msg msg = {
    1549:	*(u32 *)(r10 - 92) = r0
    1550:	r1 = 269487874
    1551:	*(u32 *)(r10 - 96) = r1
    1552:	*(u64 *)(r10 - 312) = r6
    1553:	*(u32 *)(r10 - 88) = r6
    1554:	r1 = 0
    1555:	*(u32 *)(r10 - 80) = r1
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
    1556:	r6 = *(u64 *)(r10 - 320)
    1557:	r6 &= 65535
; struct debug_msg msg = {
    1558:	*(u32 *)(r10 - 84) = r6
    1559:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    1560:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1561:	r1 = r8
    1562:	r2 = 0 ll
    1564:	r3 = 4294967295 ll
    1566:	r5 = 20
    1567:	call 25
    1568:	r2 = *(u64 *)(r10 - 336)
; if (conn_is_dns(tuple->dport))
    1569:	r1 = *(u8 *)(r2 + 0)
    1570:	r2 = *(u8 *)(r2 + 1)
    1571:	r2 <<= 8
    1572:	r2 |= r1
    1573:	r1 = 1500
    1574:	if r2 == 13568 goto +1 <LBB13_190>
    1575:	r1 = r7

LBB13_190:
    1576:	*(u64 *)(r10 - 328) = r1
    1577:	r9 = 4294967162 ll
    1579:	r2 = *(u64 *)(r10 - 216)
; void *data_end = (void *) (long) skb->data_end;
    1580:	r1 = *(u32 *)(r2 + 80)
; void *data = (void *) (long) skb->data;
    1581:	r2 = *(u32 *)(r2 + 76)
; if (data + ETH_HLEN + l3_len > data_end)
    1582:	r2 += 54
    1583:	if r2 > r1 goto -1399 <LBB13_37>
    1584:	*(u64 *)(r10 - 344) = r6
    1585:	r1 = *(u64 *)(r10 - 208)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1586:	r1 = 144115188075855996 ll
    1588:	*(u64 *)(r10 - 96) = r1
    1589:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1590:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1591:	r1 = 4043309055 ll
    1593:	r9 = *(u64 *)(r10 - 280)
    1594:	r2 = r9
    1595:	r2 &= r1
    1596:	*(u32 *)(r10 - 80) = r2
; .ip6 = *addr,
    1597:	r7 = *(u64 *)(r10 - 296)
    1598:	r7 <<= 32
    1599:	r1 = *(u64 *)(r10 - 288)
    1600:	r7 |= r1
    1601:	*(u64 *)(r10 - 88) = r7
    1602:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1603:	r2 += -96
; return map_lookup_elem(map, &key);
    1604:	r1 = 0 ll
    1606:	call 1
    1607:	*(u64 *)(r10 - 336) = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1608:	if r0 != 0 goto +1349 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1609:	r1 = 144115188075855995 ll
    1611:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1612:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1613:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1614:	r1 = 3774873599 ll
    1616:	r2 = r9
    1617:	r2 &= r1
    1618:	*(u32 *)(r10 - 80) = r2
    1619:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1620:	r2 += -96
; return map_lookup_elem(map, &key);
    1621:	r1 = 0 ll
    1623:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1624:	if r0 != 0 goto +1333 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1625:	r1 = 144115188075855994 ll
    1627:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1628:	*(u64 *)(r10 - 88) = r7
    1629:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1630:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1631:	r1 = 3238002687 ll
    1633:	r2 = r9
    1634:	r2 &= r1
    1635:	*(u32 *)(r10 - 80) = r2
    1636:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1637:	r2 += -96
; return map_lookup_elem(map, &key);
    1638:	r1 = 0 ll
    1640:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1641:	if r0 != 0 goto +1316 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1642:	r1 = 144115188075855993 ll
    1644:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1645:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1646:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1647:	r1 = 2164260863 ll
    1649:	r2 = r9
    1650:	r2 &= r1
    1651:	*(u32 *)(r10 - 80) = r2
    1652:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1653:	r2 += -96
; return map_lookup_elem(map, &key);
    1654:	r1 = 0 ll
    1656:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1657:	if r0 != 0 goto +1300 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1658:	r1 = 144115188075855992 ll
    1660:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1661:	*(u64 *)(r10 - 88) = r7
    1662:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1663:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1664:	r1 = r9
    1665:	r1 &= 16777215
    1666:	*(u32 *)(r10 - 80) = r1
    1667:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1668:	r2 += -96
; return map_lookup_elem(map, &key);
    1669:	r1 = 0 ll
    1671:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1672:	if r0 != 0 goto +1285 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1673:	r1 = 144115188075855991 ll
    1675:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1676:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1677:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1678:	r1 = r9
    1679:	r1 &= 16711679
    1680:	*(u32 *)(r10 - 80) = r1
    1681:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1682:	r2 += -96
; return map_lookup_elem(map, &key);
    1683:	r1 = 0 ll
    1685:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1686:	if r0 != 0 goto +1271 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1687:	r1 = 144115188075855990 ll
    1689:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1690:	*(u64 *)(r10 - 88) = r7
    1691:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1692:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1693:	r1 = r9
    1694:	r1 &= 16580607
    1695:	*(u32 *)(r10 - 80) = r1
    1696:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1697:	r2 += -96
; return map_lookup_elem(map, &key);
    1698:	r1 = 0 ll
    1700:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1701:	if r0 != 0 goto +1256 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1702:	r1 = 144115188075855989 ll
    1704:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1705:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1706:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1707:	r1 = r9
    1708:	r1 &= 16318463
    1709:	*(u32 *)(r10 - 80) = r1
    1710:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1711:	r2 += -96
; return map_lookup_elem(map, &key);
    1712:	r1 = 0 ll
    1714:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1715:	if r0 != 0 goto +1242 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1716:	r1 = 144115188075855988 ll
    1718:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1719:	*(u64 *)(r10 - 88) = r7
    1720:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1721:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1722:	r1 = r9
    1723:	r1 &= 15794175
    1724:	*(u32 *)(r10 - 80) = r1
    1725:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1726:	r2 += -96
; return map_lookup_elem(map, &key);
    1727:	r1 = 0 ll
    1729:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1730:	if r0 != 0 goto +1227 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1731:	r1 = 144115188075855987 ll
    1733:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1734:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1735:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1736:	r1 = r9
    1737:	r1 &= 14745599
    1738:	*(u32 *)(r10 - 80) = r1
    1739:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1740:	r2 += -96
; return map_lookup_elem(map, &key);
    1741:	r1 = 0 ll
    1743:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1744:	if r0 != 0 goto +1213 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1745:	r1 = 144115188075855986 ll
    1747:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1748:	*(u64 *)(r10 - 88) = r7
    1749:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1750:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1751:	r1 = r9
    1752:	r1 &= 12648447
    1753:	*(u32 *)(r10 - 80) = r1
    1754:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1755:	r2 += -96
; return map_lookup_elem(map, &key);
    1756:	r1 = 0 ll
    1758:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1759:	if r0 != 0 goto +1198 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1760:	r1 = 144115188075855985 ll
    1762:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1763:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1764:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1765:	r1 = r9
    1766:	r1 &= 8454143
    1767:	*(u32 *)(r10 - 80) = r1
    1768:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1769:	r2 += -96
; return map_lookup_elem(map, &key);
    1770:	r1 = 0 ll
    1772:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1773:	if r0 != 0 goto +1184 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1774:	r1 = 144115188075855984 ll
    1776:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1777:	*(u64 *)(r10 - 88) = r7
    1778:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1779:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1780:	r1 = r9
    1781:	r1 &= 65535
    1782:	*(u32 *)(r10 - 80) = r1
    1783:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1784:	r2 += -96
; return map_lookup_elem(map, &key);
    1785:	r1 = 0 ll
    1787:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1788:	if r0 != 0 goto +1169 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1789:	r1 = 144115188075855983 ll
    1791:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1792:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1793:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1794:	r1 = r9
    1795:	r1 &= 65279
    1796:	*(u32 *)(r10 - 80) = r1
    1797:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1798:	r2 += -96
; return map_lookup_elem(map, &key);
    1799:	r1 = 0 ll
    1801:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1802:	if r0 != 0 goto +1155 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1803:	r1 = 144115188075855982 ll
    1805:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1806:	*(u64 *)(r10 - 88) = r7
    1807:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1808:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1809:	r1 = r9
    1810:	r1 &= 64767
    1811:	*(u32 *)(r10 - 80) = r1
    1812:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1813:	r2 += -96
; return map_lookup_elem(map, &key);
    1814:	r1 = 0 ll
    1816:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1817:	if r0 != 0 goto +1140 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1818:	r1 = 144115188075855981 ll
    1820:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1821:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1822:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1823:	r1 = r9
    1824:	r1 &= 63743
    1825:	*(u32 *)(r10 - 80) = r1
    1826:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1827:	r2 += -96
; return map_lookup_elem(map, &key);
    1828:	r1 = 0 ll
    1830:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1831:	if r0 != 0 goto +1126 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1832:	r1 = 144115188075855980 ll
    1834:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1835:	*(u64 *)(r10 - 88) = r7
    1836:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1837:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1838:	r1 = r9
    1839:	r1 &= 61695
    1840:	*(u32 *)(r10 - 80) = r1
    1841:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1842:	r2 += -96
; return map_lookup_elem(map, &key);
    1843:	r1 = 0 ll
    1845:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1846:	if r0 != 0 goto +1111 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1847:	r1 = 144115188075855979 ll
    1849:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1850:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1851:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1852:	r1 = r9
    1853:	r1 &= 57599
    1854:	*(u32 *)(r10 - 80) = r1
    1855:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1856:	r2 += -96
; return map_lookup_elem(map, &key);
    1857:	r1 = 0 ll
    1859:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1860:	if r0 != 0 goto +1097 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1861:	r1 = 144115188075855978 ll
    1863:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1864:	*(u64 *)(r10 - 88) = r7
    1865:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1866:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1867:	r1 = r9
    1868:	r1 &= 49407
    1869:	*(u32 *)(r10 - 80) = r1
    1870:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1871:	r2 += -96
; return map_lookup_elem(map, &key);
    1872:	r1 = 0 ll
    1874:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1875:	if r0 != 0 goto +1082 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1876:	r1 = 144115188075855977 ll
    1878:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1879:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1880:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1881:	r1 = r9
    1882:	r1 &= 33023
    1883:	*(u32 *)(r10 - 80) = r1
    1884:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1885:	r2 += -96
; return map_lookup_elem(map, &key);
    1886:	r1 = 0 ll
    1888:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1889:	if r0 != 0 goto +1068 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1890:	r1 = 144115188075855976 ll
    1892:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1893:	*(u64 *)(r10 - 88) = r7
    1894:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1895:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1896:	r1 = r9
    1897:	r1 &= 255
    1898:	*(u32 *)(r10 - 80) = r1
    1899:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1900:	r2 += -96
; return map_lookup_elem(map, &key);
    1901:	r1 = 0 ll
    1903:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1904:	if r0 != 0 goto +1053 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1905:	r1 = 144115188075855975 ll
    1907:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1908:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1909:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1910:	r1 = r9
    1911:	r1 &= 254
    1912:	*(u32 *)(r10 - 80) = r1
    1913:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1914:	r2 += -96
; return map_lookup_elem(map, &key);
    1915:	r1 = 0 ll
    1917:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1918:	if r0 != 0 goto +1039 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1919:	r1 = 144115188075855974 ll
    1921:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1922:	*(u64 *)(r10 - 88) = r7
    1923:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1924:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1925:	r1 = r9
    1926:	r1 &= 252
    1927:	*(u32 *)(r10 - 80) = r1
    1928:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1929:	r2 += -96
; return map_lookup_elem(map, &key);
    1930:	r1 = 0 ll
    1932:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1933:	if r0 != 0 goto +1024 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1934:	r1 = 144115188075855973 ll
    1936:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1937:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1938:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1939:	r1 = r9
    1940:	r1 &= 248
    1941:	*(u32 *)(r10 - 80) = r1
    1942:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1943:	r2 += -96
; return map_lookup_elem(map, &key);
    1944:	r1 = 0 ll
    1946:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1947:	if r0 != 0 goto +1010 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1948:	r1 = 144115188075855972 ll
    1950:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1951:	*(u64 *)(r10 - 88) = r7
    1952:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1953:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1954:	r1 = r9
    1955:	r1 &= 240
    1956:	*(u32 *)(r10 - 80) = r1
    1957:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1958:	r2 += -96
; return map_lookup_elem(map, &key);
    1959:	r1 = 0 ll
    1961:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1962:	if r0 != 0 goto +995 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1963:	r1 = 144115188075855971 ll
    1965:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1966:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1967:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1968:	r1 = r9
    1969:	r1 &= 224
    1970:	*(u32 *)(r10 - 80) = r1
    1971:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1972:	r2 += -96
; return map_lookup_elem(map, &key);
    1973:	r1 = 0 ll
    1975:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1976:	if r0 != 0 goto +981 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1977:	r1 = 144115188075855970 ll
    1979:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1980:	*(u64 *)(r10 - 88) = r7
    1981:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1982:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1983:	r1 = r9
    1984:	r1 &= 192
    1985:	*(u32 *)(r10 - 80) = r1
    1986:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1987:	r2 += -96
; return map_lookup_elem(map, &key);
    1988:	r1 = 0 ll
    1990:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1991:	if r0 != 0 goto +966 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1992:	r1 = 144115188075855969 ll
    1994:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    1995:	*(u64 *)(r10 - 88) = r7
; addr->p4 &= GET_PREFIX(prefix);
    1996:	*(u32 *)(r10 - 76) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1997:	r1 = r9
    1998:	r1 &= 128
    1999:	*(u32 *)(r10 - 80) = r1
    2000:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2001:	r2 += -96
; return map_lookup_elem(map, &key);
    2002:	r1 = 0 ll
    2004:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2005:	if r0 != 0 goto +952 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2006:	r1 = 144115188075855968 ll
    2008:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    2009:	*(u64 *)(r10 - 88) = r7
    2010:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2011:	*(u64 *)(r10 - 80) = r6
    2012:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2013:	r2 += -96
; return map_lookup_elem(map, &key);
    2014:	r1 = 0 ll
    2016:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2017:	if r0 != 0 goto +940 <LBB13_283>
; .ip6 = *addr,
    2018:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2019:	r1 = 144115188075855967 ll
    2021:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2022:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2023:	r1 = 4278190079 ll
    2025:	r2 = *(u64 *)(r10 - 296)
    2026:	r2 &= r1
    2027:	*(u32 *)(r10 - 84) = r2
    2028:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2029:	r2 += -96
; return map_lookup_elem(map, &key);
    2030:	r1 = 0 ll
    2032:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2033:	if r0 != 0 goto +924 <LBB13_283>
; .ip6 = *addr,
    2034:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2035:	r1 = 144115188075855966 ll
    2037:	*(u64 *)(r10 - 96) = r1
    2038:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2039:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2040:	r1 = 4244635647 ll
    2042:	r2 = *(u64 *)(r10 - 296)
    2043:	r2 &= r1
    2044:	*(u32 *)(r10 - 84) = r2
    2045:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2046:	r2 += -96
; return map_lookup_elem(map, &key);
    2047:	r1 = 0 ll
    2049:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2050:	if r0 != 0 goto +907 <LBB13_283>
; .ip6 = *addr,
    2051:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2052:	r1 = 144115188075855965 ll
    2054:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2055:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2056:	r1 = 4177526783 ll
    2058:	r2 = *(u64 *)(r10 - 296)
    2059:	r2 &= r1
    2060:	*(u32 *)(r10 - 84) = r2
    2061:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2062:	r2 += -96
; return map_lookup_elem(map, &key);
    2063:	r1 = 0 ll
    2065:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2066:	if r0 != 0 goto +891 <LBB13_283>
; .ip6 = *addr,
    2067:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2068:	r1 = 144115188075855964 ll
    2070:	*(u64 *)(r10 - 96) = r1
    2071:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2072:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2073:	r1 = 4043309055 ll
    2075:	r2 = *(u64 *)(r10 - 296)
    2076:	r2 &= r1
    2077:	*(u32 *)(r10 - 84) = r2
    2078:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2079:	r2 += -96
; return map_lookup_elem(map, &key);
    2080:	r1 = 0 ll
    2082:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2083:	if r0 != 0 goto +874 <LBB13_283>
; .ip6 = *addr,
    2084:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2085:	r1 = 144115188075855963 ll
    2087:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2088:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2089:	r1 = 3774873599 ll
    2091:	r2 = *(u64 *)(r10 - 296)
    2092:	r2 &= r1
    2093:	*(u32 *)(r10 - 84) = r2
    2094:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2095:	r2 += -96
; return map_lookup_elem(map, &key);
    2096:	r1 = 0 ll
    2098:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2099:	if r0 != 0 goto +858 <LBB13_283>
; .ip6 = *addr,
    2100:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2101:	r1 = 144115188075855962 ll
    2103:	*(u64 *)(r10 - 96) = r1
    2104:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2105:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2106:	r1 = 3238002687 ll
    2108:	r2 = *(u64 *)(r10 - 296)
    2109:	r2 &= r1
    2110:	*(u32 *)(r10 - 84) = r2
    2111:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2112:	r2 += -96
; return map_lookup_elem(map, &key);
    2113:	r1 = 0 ll
    2115:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2116:	if r0 != 0 goto +841 <LBB13_283>
; .ip6 = *addr,
    2117:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2118:	r1 = 144115188075855961 ll
    2120:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2121:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2122:	r1 = 2164260863 ll
    2124:	r2 = *(u64 *)(r10 - 296)
    2125:	r2 &= r1
    2126:	*(u32 *)(r10 - 84) = r2
    2127:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2128:	r2 += -96
; return map_lookup_elem(map, &key);
    2129:	r1 = 0 ll
    2131:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2132:	if r0 != 0 goto +825 <LBB13_283>
; .ip6 = *addr,
    2133:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2134:	r1 = 144115188075855960 ll
    2136:	*(u64 *)(r10 - 96) = r1
    2137:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2138:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2139:	r1 = *(u64 *)(r10 - 296)
    2140:	r1 &= 16777215
    2141:	*(u32 *)(r10 - 84) = r1
    2142:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2143:	r2 += -96
; return map_lookup_elem(map, &key);
    2144:	r1 = 0 ll
    2146:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2147:	if r0 != 0 goto +810 <LBB13_283>
; .ip6 = *addr,
    2148:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2149:	r1 = 144115188075855959 ll
    2151:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2152:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2153:	r1 = *(u64 *)(r10 - 296)
    2154:	r1 &= 16711679
    2155:	*(u32 *)(r10 - 84) = r1
    2156:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2157:	r2 += -96
; return map_lookup_elem(map, &key);
    2158:	r1 = 0 ll
    2160:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2161:	if r0 != 0 goto +796 <LBB13_283>
; .ip6 = *addr,
    2162:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2163:	r1 = 144115188075855958 ll
    2165:	*(u64 *)(r10 - 96) = r1
    2166:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2167:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2168:	r1 = *(u64 *)(r10 - 296)
    2169:	r1 &= 16580607
    2170:	*(u32 *)(r10 - 84) = r1
    2171:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2172:	r2 += -96
; return map_lookup_elem(map, &key);
    2173:	r1 = 0 ll
    2175:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2176:	if r0 != 0 goto +781 <LBB13_283>
; .ip6 = *addr,
    2177:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2178:	r1 = 144115188075855957 ll
    2180:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2181:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2182:	r1 = *(u64 *)(r10 - 296)
    2183:	r1 &= 16318463
    2184:	*(u32 *)(r10 - 84) = r1
    2185:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2186:	r2 += -96
; return map_lookup_elem(map, &key);
    2187:	r1 = 0 ll
    2189:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2190:	if r0 != 0 goto +767 <LBB13_283>
; .ip6 = *addr,
    2191:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2192:	r1 = 144115188075855956 ll
    2194:	*(u64 *)(r10 - 96) = r1
    2195:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2196:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2197:	r1 = *(u64 *)(r10 - 296)
    2198:	r1 &= 15794175
    2199:	*(u32 *)(r10 - 84) = r1
    2200:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2201:	r2 += -96
; return map_lookup_elem(map, &key);
    2202:	r1 = 0 ll
    2204:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2205:	if r0 != 0 goto +752 <LBB13_283>
; .ip6 = *addr,
    2206:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2207:	r1 = 144115188075855955 ll
    2209:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2210:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2211:	r1 = *(u64 *)(r10 - 296)
    2212:	r1 &= 14745599
    2213:	*(u32 *)(r10 - 84) = r1
    2214:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2215:	r2 += -96
; return map_lookup_elem(map, &key);
    2216:	r1 = 0 ll
    2218:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2219:	if r0 != 0 goto +738 <LBB13_283>
; .ip6 = *addr,
    2220:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2221:	r1 = 144115188075855954 ll
    2223:	*(u64 *)(r10 - 96) = r1
    2224:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2225:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2226:	r1 = *(u64 *)(r10 - 296)
    2227:	r1 &= 12648447
    2228:	*(u32 *)(r10 - 84) = r1
    2229:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2230:	r2 += -96
; return map_lookup_elem(map, &key);
    2231:	r1 = 0 ll
    2233:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2234:	if r0 != 0 goto +723 <LBB13_283>
; .ip6 = *addr,
    2235:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2236:	r1 = 144115188075855953 ll
    2238:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2239:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2240:	r1 = *(u64 *)(r10 - 296)
    2241:	r1 &= 8454143
    2242:	*(u32 *)(r10 - 84) = r1
    2243:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2244:	r2 += -96
; return map_lookup_elem(map, &key);
    2245:	r1 = 0 ll
    2247:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2248:	if r0 != 0 goto +709 <LBB13_283>
; .ip6 = *addr,
    2249:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2250:	r1 = 144115188075855952 ll
    2252:	*(u64 *)(r10 - 96) = r1
    2253:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2254:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2255:	r1 = *(u64 *)(r10 - 296)
    2256:	r1 &= 65535
    2257:	*(u32 *)(r10 - 84) = r1
    2258:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2259:	r2 += -96
; return map_lookup_elem(map, &key);
    2260:	r1 = 0 ll
    2262:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2263:	if r0 != 0 goto +694 <LBB13_283>
; .ip6 = *addr,
    2264:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2265:	r1 = 144115188075855951 ll
    2267:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2268:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2269:	r1 = *(u64 *)(r10 - 296)
    2270:	r1 &= 65279
    2271:	*(u32 *)(r10 - 84) = r1
    2272:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2273:	r2 += -96
; return map_lookup_elem(map, &key);
    2274:	r1 = 0 ll
    2276:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2277:	if r0 != 0 goto +680 <LBB13_283>
; .ip6 = *addr,
    2278:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2279:	r1 = 144115188075855950 ll
    2281:	*(u64 *)(r10 - 96) = r1
    2282:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2283:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2284:	r1 = *(u64 *)(r10 - 296)
    2285:	r1 &= 64767
    2286:	*(u32 *)(r10 - 84) = r1
    2287:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2288:	r2 += -96
; return map_lookup_elem(map, &key);
    2289:	r1 = 0 ll
    2291:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2292:	if r0 != 0 goto +665 <LBB13_283>
; .ip6 = *addr,
    2293:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2294:	r1 = 144115188075855949 ll
    2296:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2297:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2298:	r1 = *(u64 *)(r10 - 296)
    2299:	r1 &= 63743
    2300:	*(u32 *)(r10 - 84) = r1
    2301:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2302:	r2 += -96
; return map_lookup_elem(map, &key);
    2303:	r1 = 0 ll
    2305:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2306:	if r0 != 0 goto +651 <LBB13_283>
; .ip6 = *addr,
    2307:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2308:	r1 = 144115188075855948 ll
    2310:	*(u64 *)(r10 - 96) = r1
    2311:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2312:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2313:	r1 = *(u64 *)(r10 - 296)
    2314:	r1 &= 61695
    2315:	*(u32 *)(r10 - 84) = r1
    2316:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2317:	r2 += -96
; return map_lookup_elem(map, &key);
    2318:	r1 = 0 ll
    2320:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2321:	if r0 != 0 goto +636 <LBB13_283>
; .ip6 = *addr,
    2322:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2323:	r1 = 144115188075855947 ll
    2325:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2326:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2327:	r1 = *(u64 *)(r10 - 296)
    2328:	r1 &= 57599
    2329:	*(u32 *)(r10 - 84) = r1
    2330:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2331:	r2 += -96
; return map_lookup_elem(map, &key);
    2332:	r1 = 0 ll
    2334:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2335:	if r0 != 0 goto +622 <LBB13_283>
; .ip6 = *addr,
    2336:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2337:	r1 = 144115188075855946 ll
    2339:	*(u64 *)(r10 - 96) = r1
    2340:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2341:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2342:	r1 = *(u64 *)(r10 - 296)
    2343:	r1 &= 49407
    2344:	*(u32 *)(r10 - 84) = r1
    2345:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2346:	r2 += -96
; return map_lookup_elem(map, &key);
    2347:	r1 = 0 ll
    2349:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2350:	if r0 != 0 goto +607 <LBB13_283>
; .ip6 = *addr,
    2351:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2352:	r1 = 144115188075855945 ll
    2354:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2355:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2356:	r1 = *(u64 *)(r10 - 296)
    2357:	r1 &= 33023
    2358:	*(u32 *)(r10 - 84) = r1
    2359:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2360:	r2 += -96
; return map_lookup_elem(map, &key);
    2361:	r1 = 0 ll
    2363:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2364:	if r0 != 0 goto +593 <LBB13_283>
; .ip6 = *addr,
    2365:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2366:	r1 = 144115188075855944 ll
    2368:	*(u64 *)(r10 - 96) = r1
    2369:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2370:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2371:	r1 = *(u64 *)(r10 - 296)
    2372:	r1 &= 255
    2373:	*(u32 *)(r10 - 84) = r1
    2374:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2375:	r2 += -96
; return map_lookup_elem(map, &key);
    2376:	r1 = 0 ll
    2378:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2379:	if r0 != 0 goto +578 <LBB13_283>
; .ip6 = *addr,
    2380:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2381:	r1 = 144115188075855943 ll
    2383:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2384:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2385:	r1 = *(u64 *)(r10 - 296)
    2386:	r1 &= 254
    2387:	*(u32 *)(r10 - 84) = r1
    2388:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2389:	r2 += -96
; return map_lookup_elem(map, &key);
    2390:	r1 = 0 ll
    2392:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2393:	if r0 != 0 goto +564 <LBB13_283>
; .ip6 = *addr,
    2394:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2395:	r1 = 144115188075855942 ll
    2397:	*(u64 *)(r10 - 96) = r1
    2398:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2399:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2400:	r1 = *(u64 *)(r10 - 296)
    2401:	r1 &= 252
    2402:	*(u32 *)(r10 - 84) = r1
    2403:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2404:	r2 += -96
; return map_lookup_elem(map, &key);
    2405:	r1 = 0 ll
    2407:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2408:	if r0 != 0 goto +549 <LBB13_283>
; .ip6 = *addr,
    2409:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2410:	r1 = 144115188075855941 ll
    2412:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2413:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2414:	r1 = *(u64 *)(r10 - 296)
    2415:	r1 &= 248
    2416:	*(u32 *)(r10 - 84) = r1
    2417:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2418:	r2 += -96
; return map_lookup_elem(map, &key);
    2419:	r1 = 0 ll
    2421:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2422:	if r0 != 0 goto +535 <LBB13_283>
; .ip6 = *addr,
    2423:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2424:	r1 = 144115188075855940 ll
    2426:	*(u64 *)(r10 - 96) = r1
    2427:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2428:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2429:	r1 = *(u64 *)(r10 - 296)
    2430:	r1 &= 240
    2431:	*(u32 *)(r10 - 84) = r1
    2432:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2433:	r2 += -96
; return map_lookup_elem(map, &key);
    2434:	r1 = 0 ll
    2436:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2437:	if r0 != 0 goto +520 <LBB13_283>
; .ip6 = *addr,
    2438:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2439:	r1 = 144115188075855939 ll
    2441:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2442:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2443:	r1 = *(u64 *)(r10 - 296)
    2444:	r1 &= 224
    2445:	*(u32 *)(r10 - 84) = r1
    2446:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2447:	r2 += -96
; return map_lookup_elem(map, &key);
    2448:	r1 = 0 ll
    2450:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2451:	if r0 != 0 goto +506 <LBB13_283>
; .ip6 = *addr,
    2452:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2453:	r1 = 144115188075855938 ll
    2455:	*(u64 *)(r10 - 96) = r1
    2456:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2457:	*(u64 *)(r10 - 80) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2458:	r1 = *(u64 *)(r10 - 296)
    2459:	r1 &= 192
    2460:	*(u32 *)(r10 - 84) = r1
    2461:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2462:	r2 += -96
; return map_lookup_elem(map, &key);
    2463:	r1 = 0 ll
    2465:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2466:	if r0 != 0 goto +491 <LBB13_283>
; .ip6 = *addr,
    2467:	*(u64 *)(r10 - 88) = r7
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2468:	r1 = 144115188075855937 ll
    2470:	*(u64 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2471:	*(u64 *)(r10 - 80) = r6
    2472:	r1 = *(u64 *)(r10 - 296)
; addr->p2 &= GET_PREFIX(prefix);
    2473:	r1 &= 128
    2474:	*(u32 *)(r10 - 84) = r1
    2475:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2476:	r2 += -96
; return map_lookup_elem(map, &key);
    2477:	r1 = 0 ll
    2479:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2480:	if r0 != 0 goto +477 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2481:	r1 = 144115188075855936 ll
    2483:	*(u64 *)(r10 - 96) = r1
; .ip6 = *addr,
    2484:	r1 = *(u64 *)(r10 - 288)
    2485:	*(u32 *)(r10 - 88) = r1
    2486:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2487:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2488:	*(u64 *)(r10 - 80) = r6
    2489:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2490:	r2 += -96
; return map_lookup_elem(map, &key);
    2491:	r1 = 0 ll
    2493:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2494:	if r0 != 0 goto +463 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2495:	r1 = 144115188075855935 ll
    2497:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2498:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2499:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2500:	r1 = 4278190079 ll
    2502:	r2 = *(u64 *)(r10 - 288)
    2503:	r2 &= r1
    2504:	*(u32 *)(r10 - 88) = r2
    2505:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2506:	r2 += -96
; return map_lookup_elem(map, &key);
    2507:	r1 = 0 ll
    2509:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2510:	if r0 != 0 goto +447 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2511:	r1 = 144115188075855934 ll
    2513:	*(u64 *)(r10 - 96) = r1
    2514:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2515:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2516:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2517:	r1 = 4244635647 ll
    2519:	r2 = *(u64 *)(r10 - 288)
    2520:	r2 &= r1
    2521:	*(u32 *)(r10 - 88) = r2
    2522:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2523:	r2 += -96
; return map_lookup_elem(map, &key);
    2524:	r1 = 0 ll
    2526:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2527:	if r0 != 0 goto +430 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2528:	r1 = 144115188075855933 ll
    2530:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2531:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2532:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2533:	r1 = 4177526783 ll
    2535:	r2 = *(u64 *)(r10 - 288)
    2536:	r2 &= r1
    2537:	*(u32 *)(r10 - 88) = r2
    2538:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2539:	r2 += -96
; return map_lookup_elem(map, &key);
    2540:	r1 = 0 ll
    2542:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2543:	if r0 != 0 goto +414 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2544:	r1 = 144115188075855932 ll
    2546:	*(u64 *)(r10 - 96) = r1
    2547:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2548:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2549:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2550:	r1 = 4043309055 ll
    2552:	r2 = *(u64 *)(r10 - 288)
    2553:	r2 &= r1
    2554:	*(u32 *)(r10 - 88) = r2
    2555:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2556:	r2 += -96
; return map_lookup_elem(map, &key);
    2557:	r1 = 0 ll
    2559:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2560:	if r0 != 0 goto +397 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2561:	r1 = 144115188075855931 ll
    2563:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2564:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2565:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2566:	r1 = 3774873599 ll
    2568:	r2 = *(u64 *)(r10 - 288)
    2569:	r2 &= r1
    2570:	*(u32 *)(r10 - 88) = r2
    2571:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2572:	r2 += -96
; return map_lookup_elem(map, &key);
    2573:	r1 = 0 ll
    2575:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2576:	if r0 != 0 goto +381 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2577:	r1 = 144115188075855930 ll
    2579:	*(u64 *)(r10 - 96) = r1
    2580:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2581:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2582:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2583:	r1 = 3238002687 ll
    2585:	r2 = *(u64 *)(r10 - 288)
    2586:	r2 &= r1
    2587:	*(u32 *)(r10 - 88) = r2
    2588:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2589:	r2 += -96
; return map_lookup_elem(map, &key);
    2590:	r1 = 0 ll
    2592:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2593:	if r0 != 0 goto +364 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2594:	r1 = 144115188075855929 ll
    2596:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2597:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2598:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2599:	r1 = 2164260863 ll
    2601:	r2 = *(u64 *)(r10 - 288)
    2602:	r2 &= r1
    2603:	*(u32 *)(r10 - 88) = r2
    2604:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2605:	r2 += -96
; return map_lookup_elem(map, &key);
    2606:	r1 = 0 ll
    2608:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2609:	if r0 != 0 goto +348 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2610:	r1 = 144115188075855928 ll
    2612:	*(u64 *)(r10 - 96) = r1
    2613:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2614:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2615:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2616:	r1 = *(u64 *)(r10 - 288)
    2617:	r1 &= 16777215
    2618:	*(u32 *)(r10 - 88) = r1
    2619:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2620:	r2 += -96
; return map_lookup_elem(map, &key);
    2621:	r1 = 0 ll
    2623:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2624:	if r0 != 0 goto +333 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2625:	r1 = 144115188075855927 ll
    2627:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2628:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2629:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2630:	r1 = *(u64 *)(r10 - 288)
    2631:	r1 &= 16711679
    2632:	*(u32 *)(r10 - 88) = r1
    2633:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2634:	r2 += -96
; return map_lookup_elem(map, &key);
    2635:	r1 = 0 ll
    2637:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2638:	if r0 != 0 goto +319 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2639:	r1 = 144115188075855926 ll
    2641:	*(u64 *)(r10 - 96) = r1
    2642:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2643:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2644:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2645:	r1 = *(u64 *)(r10 - 288)
    2646:	r1 &= 16580607
    2647:	*(u32 *)(r10 - 88) = r1
    2648:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2649:	r2 += -96
; return map_lookup_elem(map, &key);
    2650:	r1 = 0 ll
    2652:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2653:	if r0 != 0 goto +304 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2654:	r1 = 144115188075855925 ll
    2656:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2657:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2658:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2659:	r1 = *(u64 *)(r10 - 288)
    2660:	r1 &= 16318463
    2661:	*(u32 *)(r10 - 88) = r1
    2662:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2663:	r2 += -96
; return map_lookup_elem(map, &key);
    2664:	r1 = 0 ll
    2666:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2667:	if r0 != 0 goto +290 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2668:	r1 = 144115188075855924 ll
    2670:	*(u64 *)(r10 - 96) = r1
    2671:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2672:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2673:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2674:	r1 = *(u64 *)(r10 - 288)
    2675:	r1 &= 15794175
    2676:	*(u32 *)(r10 - 88) = r1
    2677:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2678:	r2 += -96
; return map_lookup_elem(map, &key);
    2679:	r1 = 0 ll
    2681:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2682:	if r0 != 0 goto +275 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2683:	r1 = 144115188075855923 ll
    2685:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2686:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2687:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2688:	r1 = *(u64 *)(r10 - 288)
    2689:	r1 &= 14745599
    2690:	*(u32 *)(r10 - 88) = r1
    2691:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2692:	r2 += -96
; return map_lookup_elem(map, &key);
    2693:	r1 = 0 ll
    2695:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2696:	if r0 != 0 goto +261 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2697:	r1 = 144115188075855922 ll
    2699:	*(u64 *)(r10 - 96) = r1
    2700:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2701:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2702:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2703:	r1 = *(u64 *)(r10 - 288)
    2704:	r1 &= 12648447
    2705:	*(u32 *)(r10 - 88) = r1
    2706:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2707:	r2 += -96
; return map_lookup_elem(map, &key);
    2708:	r1 = 0 ll
    2710:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2711:	if r0 != 0 goto +246 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2712:	r1 = 144115188075855921 ll
    2714:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2715:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2716:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2717:	r1 = *(u64 *)(r10 - 288)
    2718:	r1 &= 8454143
    2719:	*(u32 *)(r10 - 88) = r1
    2720:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2721:	r2 += -96
; return map_lookup_elem(map, &key);
    2722:	r1 = 0 ll
    2724:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2725:	if r0 != 0 goto +232 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2726:	r1 = 144115188075855920 ll
    2728:	*(u64 *)(r10 - 96) = r1
    2729:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2730:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2731:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2732:	r1 = *(u64 *)(r10 - 288)
    2733:	r1 &= 65535
    2734:	*(u32 *)(r10 - 88) = r1
    2735:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2736:	r2 += -96
; return map_lookup_elem(map, &key);
    2737:	r1 = 0 ll
    2739:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2740:	if r0 != 0 goto +217 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2741:	r1 = 144115188075855919 ll
    2743:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2744:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2745:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2746:	r1 = *(u64 *)(r10 - 288)
    2747:	r1 &= 65279
    2748:	*(u32 *)(r10 - 88) = r1
    2749:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2750:	r2 += -96
; return map_lookup_elem(map, &key);
    2751:	r1 = 0 ll
    2753:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2754:	if r0 != 0 goto +203 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2755:	r1 = 144115188075855918 ll
    2757:	*(u64 *)(r10 - 96) = r1
    2758:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2759:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2760:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2761:	r1 = *(u64 *)(r10 - 288)
    2762:	r1 &= 64767
    2763:	*(u32 *)(r10 - 88) = r1
    2764:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2765:	r2 += -96
; return map_lookup_elem(map, &key);
    2766:	r1 = 0 ll
    2768:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2769:	if r0 != 0 goto +188 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2770:	r1 = 144115188075855917 ll
    2772:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2773:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2774:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2775:	r1 = *(u64 *)(r10 - 288)
    2776:	r1 &= 63743
    2777:	*(u32 *)(r10 - 88) = r1
    2778:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2779:	r2 += -96
; return map_lookup_elem(map, &key);
    2780:	r1 = 0 ll
    2782:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2783:	if r0 != 0 goto +174 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2784:	r1 = 144115188075855916 ll
    2786:	*(u64 *)(r10 - 96) = r1
    2787:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2788:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2789:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2790:	r1 = *(u64 *)(r10 - 288)
    2791:	r1 &= 61695
    2792:	*(u32 *)(r10 - 88) = r1
    2793:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2794:	r2 += -96
; return map_lookup_elem(map, &key);
    2795:	r1 = 0 ll
    2797:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2798:	if r0 != 0 goto +159 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2799:	r1 = 144115188075855915 ll
    2801:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2802:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2803:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2804:	r1 = *(u64 *)(r10 - 288)
    2805:	r1 &= 57599
    2806:	*(u32 *)(r10 - 88) = r1
    2807:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2808:	r2 += -96
; return map_lookup_elem(map, &key);
    2809:	r1 = 0 ll
    2811:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2812:	if r0 != 0 goto +145 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2813:	r1 = 144115188075855914 ll
    2815:	*(u64 *)(r10 - 96) = r1
    2816:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2817:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2818:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2819:	r1 = *(u64 *)(r10 - 288)
    2820:	r1 &= 49407
    2821:	*(u32 *)(r10 - 88) = r1
    2822:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2823:	r2 += -96
; return map_lookup_elem(map, &key);
    2824:	r1 = 0 ll
    2826:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2827:	if r0 != 0 goto +130 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2828:	r1 = 144115188075855913 ll
    2830:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2831:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2832:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2833:	r1 = *(u64 *)(r10 - 288)
    2834:	r1 &= 33023
    2835:	*(u32 *)(r10 - 88) = r1
    2836:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2837:	r2 += -96
; return map_lookup_elem(map, &key);
    2838:	r1 = 0 ll
    2840:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2841:	if r0 != 0 goto +116 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2842:	r1 = 144115188075855912 ll
    2844:	*(u64 *)(r10 - 96) = r1
    2845:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2846:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2847:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2848:	r1 = *(u64 *)(r10 - 288)
    2849:	r1 &= 255
    2850:	*(u32 *)(r10 - 88) = r1
    2851:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2852:	r2 += -96
; return map_lookup_elem(map, &key);
    2853:	r1 = 0 ll
    2855:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2856:	if r0 != 0 goto +101 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2857:	r1 = 144115188075855911 ll
    2859:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2860:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2861:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2862:	r1 = *(u64 *)(r10 - 288)
    2863:	r1 &= 254
    2864:	*(u32 *)(r10 - 88) = r1
    2865:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2866:	r2 += -96
; return map_lookup_elem(map, &key);
    2867:	r1 = 0 ll
    2869:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2870:	if r0 != 0 goto +87 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2871:	r1 = 144115188075855910 ll
    2873:	*(u64 *)(r10 - 96) = r1
    2874:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2875:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2876:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2877:	r1 = *(u64 *)(r10 - 288)
    2878:	r1 &= 252
    2879:	*(u32 *)(r10 - 88) = r1
    2880:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2881:	r2 += -96
; return map_lookup_elem(map, &key);
    2882:	r1 = 0 ll
    2884:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2885:	if r0 != 0 goto +72 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2886:	r1 = 144115188075855909 ll
    2888:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2889:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2890:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2891:	r1 = *(u64 *)(r10 - 288)
    2892:	r1 &= 248
    2893:	*(u32 *)(r10 - 88) = r1
    2894:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2895:	r2 += -96
; return map_lookup_elem(map, &key);
    2896:	r1 = 0 ll
    2898:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2899:	if r0 != 0 goto +58 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2900:	r1 = 144115188075855908 ll
    2902:	*(u64 *)(r10 - 96) = r1
    2903:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2904:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2905:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2906:	r1 = *(u64 *)(r10 - 288)
    2907:	r1 &= 240
    2908:	*(u32 *)(r10 - 88) = r1
    2909:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2910:	r2 += -96
; return map_lookup_elem(map, &key);
    2911:	r1 = 0 ll
    2913:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2914:	if r0 != 0 goto +43 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2915:	r1 = 144115188075855907 ll
    2917:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2918:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2919:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2920:	r1 = *(u64 *)(r10 - 288)
    2921:	r1 &= 224
    2922:	*(u32 *)(r10 - 88) = r1
    2923:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2924:	r2 += -96
; return map_lookup_elem(map, &key);
    2925:	r1 = 0 ll
    2927:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2928:	if r0 != 0 goto +29 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2929:	r1 = 144115188075855906 ll
    2931:	*(u64 *)(r10 - 96) = r1
    2932:	r6 = 0
; addr->p2 &= GET_PREFIX(prefix);
    2933:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2934:	*(u64 *)(r10 - 80) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2935:	r1 = *(u64 *)(r10 - 288)
    2936:	r1 &= 192
    2937:	*(u32 *)(r10 - 88) = r1
    2938:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2939:	r2 += -96
; return map_lookup_elem(map, &key);
    2940:	r1 = 0 ll
    2942:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2943:	if r0 != 0 goto +14 <LBB13_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2944:	r1 = 144115188075855905 ll
    2946:	*(u64 *)(r10 - 96) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2947:	*(u32 *)(r10 - 84) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2948:	*(u64 *)(r10 - 80) = r6
    2949:	r1 = *(u64 *)(r10 - 288)
; addr->p1 &= GET_PREFIX(prefix);
    2950:	r1 &= 128
    2951:	*(u32 *)(r10 - 88) = r1
    2952:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2953:	r2 += -96
; return map_lookup_elem(map, &key);
    2954:	r1 = 0 ll
    2956:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2957:	if r0 == 0 goto +1382 <LBB13_463>

LBB13_283:
; if (info != NULL && info->sec_label) {
    2958:	r6 = *(u32 *)(r0 + 0)
    2959:	if r6 != 0 goto +7 <LBB13_286>
    2960:	r6 = 2
    2961:	r1 = *(u64 *)(r10 - 208)
; *dstID = WORLD_ID;
    2962:	*(u32 *)(r1 + 0) = r6
    2963:	r9 = r1
    2964:	r7 = 55

LBB13_285:
    2965:	r1 = 0
    2966:	goto +5 <LBB13_287>

LBB13_286:
    2967:	r1 = *(u64 *)(r10 - 208)
; *dstID = info->sec_label;
    2968:	*(u32 *)(r1 + 0) = r6
    2969:	r9 = r1
    2970:	r7 = 55
; tunnel_endpoint = info->tunnel_endpoint;
    2971:	r1 = *(u32 *)(r0 + 4)

LBB13_287:
    2972:	*(u64 *)(r10 - 352) = r1
    2973:	r8 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    2974:	r1 = r8
    2975:	call 34
; struct debug_msg msg = {
    2976:	*(u8 *)(r10 - 95) = r7
    2977:	r1 = 2
    2978:	*(u8 *)(r10 - 96) = r1
    2979:	r1 = 4112
    2980:	*(u16 *)(r10 - 94) = r1
    2981:	*(u32 *)(r10 - 92) = r0
    2982:	r1 = *(u64 *)(r10 - 240)
    2983:	*(u32 *)(r10 - 88) = r1
    2984:	*(u32 *)(r10 - 84) = r6
    2985:	r1 = 0
    2986:	*(u32 *)(r10 - 80) = r1
    2987:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    2988:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    2989:	r1 = r8
    2990:	r2 = 0 ll
    2992:	r3 = 4294967295 ll
    2994:	r5 = 20
    2995:	call 25
; verdict = policy_can_egress6(skb, tuple, *dstID,
    2996:	r7 = *(u32 *)(r9 + 0)
    2997:	r2 = *(u64 *)(r10 - 200)
; return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
    2998:	r4 = *(u8 *)(r2 + 36)
    2999:	r1 = *(u8 *)(r2 + 32)
    3000:	r9 = *(u8 *)(r2 + 33)
    3001:	r3 = 1
    3002:	r2 = 1
; struct policy_key key = {
    3003:	*(u64 *)(r10 - 296) = r2
    3004:	*(u8 *)(r10 - 129) = r3
; return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
    3005:	r9 <<= 8
    3006:	r9 |= r1
; struct policy_key key = {
    3007:	*(u32 *)(r10 - 136) = r7
    3008:	*(u64 *)(r10 - 288) = r4
    3009:	*(u8 *)(r10 - 130) = r4
    3010:	*(u16 *)(r10 - 132) = r9
    3011:	r2 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3012:	r2 += -136
; policy = map_lookup_elem(map, &key);
    3013:	r1 = 0 ll
    3015:	call 1
    3016:	r6 = r0
; if (likely(policy)) {
    3017:	if r6 == 0 goto +1218 <LBB13_452>
    3018:	r8 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    3019:	r1 = r8
    3020:	call 34
; struct debug_msg msg = {
    3021:	*(u32 *)(r10 - 92) = r0
    3022:	r1 = 269497090
    3023:	*(u32 *)(r10 - 96) = r1
    3024:	*(u32 *)(r10 - 88) = r7
    3025:	r1 = 2
    3026:	*(u32 *)(r10 - 84) = r1
; dport << 16 | proto);
    3027:	r9 <<= 16
    3028:	r1 = *(u64 *)(r10 - 288)
    3029:	r9 |= r1
; struct debug_msg msg = {
    3030:	*(u32 *)(r10 - 80) = r9
    3031:	r4 = r10
; static inline void cilium_dbg3(struct __sk_buff *skb, __u8 type, __u32 arg1,
    3032:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3033:	r1 = r8
    3034:	r2 = 0 ll
    3036:	r3 = 4294967295 ll
    3038:	r5 = 20
    3039:	call 25
; __sync_fetch_and_add(&policy->packets, 1);
    3040:	r1 = *(u64 *)(r10 - 296)
    3041:	lock *(u64 *)(r6 + 8) += r1
; __sync_fetch_and_add(&policy->bytes, skb->len);
    3042:	r1 = *(u32 *)(r8 + 0)

LBB13_289:
    3043:	lock *(u64 *)(r6 + 16) += r1
    3044:	r7 = *(u64 *)(r10 - 336)
; return policy->proxy_port;
    3045:	r4 = *(u16 *)(r6 + 0)

LBB13_290:
    3046:	r6 = *(u64 *)(r10 - 200)

LBB13_291:
    3047:	r1 = *(u64 *)(r10 - 312)
    3048:	r1 <<= 32
    3049:	r1 >>= 32
; switch (ret) {
    3050:	r2 = r1
    3051:	r2 += -2
    3052:	if r2 < 2 goto +81 <LBB13_302>
    3053:	if r1 == 1 goto +210 <LBB13_309>
    3054:	r9 = 4294967163 ll
    3056:	if r1 != 0 goto -2872 <LBB13_37>
; if (tuple->nexthdr == IPPROTO_TCP) {
    3057:	r1 = *(u8 *)(r6 + 36)
    3058:	r2 = 0
; struct ct_entry entry = { };
    3059:	*(u64 *)(r10 - 64) = r2
    3060:	*(u64 *)(r10 - 56) = r2
    3061:	*(u64 *)(r10 - 48) = r2
    3062:	*(u64 *)(r10 - 72) = r2
    3063:	*(u64 *)(r10 - 80) = r2
    3064:	*(u64 *)(r10 - 88) = r2
    3065:	*(u64 *)(r10 - 96) = r2
    3066:	r7 = *(u64 *)(r10 - 264)
; entry.rev_nat_index = ct_state->rev_nat_index;
    3067:	*(u16 *)(r10 - 58) = r7
; entry.slave = ct_state->slave;
    3068:	r2 = *(u64 *)(r10 - 248)
    3069:	*(u16 *)(r10 - 56) = r2
; ret = ct_create6(get_ct_map6(tuple), tuple, skb, CT_EGRESS, &ct_state_new);
    3070:	r6 = 0 ll
    3072:	if r1 == 6 goto +2 <LBB13_296>
    3073:	r6 = 0 ll

LBB13_296:
    3075:	*(u64 *)(r10 - 248) = r4
    3076:	r2 = *(u64 *)(r10 - 256)
; entry.lb_loopback = ct_state->loopback;
    3077:	r2 <<= 3
    3078:	*(u16 *)(r10 - 60) = r2
; if (tcp) {
    3079:	if r1 != 6 goto +1 <LBB13_298>
; entry->seen_non_syn |= !syn;
    3080:	*(u16 *)(r10 - 60) = r2

LBB13_298:
; return ktime_get_ns();
    3081:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3082:	r0 /= 1000000000
; entry->lifetime = now + lifetime;
    3083:	r1 = r0
    3084:	r1 += 60
    3085:	*(u32 *)(r10 - 64) = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3086:	r1 = r0
    3087:	r1 <<= 32
    3088:	r1 >>= 32
; if (*last_report + CT_REPORT_INTERVAL < now ||
    3089:	r2 = *(u32 *)(r10 - 48)
    3090:	r2 += 5
    3091:	r2 <<= 32
    3092:	r2 >>= 32
    3093:	if r2 >= r1 goto +1 <LBB13_300>
; *last_report = now;
    3094:	*(u32 *)(r10 - 48) = r0

LBB13_300:
    3095:	r1 = 1
; entry.tx_packets = 1;
    3096:	*(u64 *)(r10 - 80) = r1
    3097:	r8 = *(u64 *)(r10 - 216)
; entry.tx_bytes = skb->len;
    3098:	r1 = *(u32 *)(r8 + 0)
    3099:	*(u64 *)(r10 - 72) = r1
; uint32_t hash = get_hash_recalc(skb);
    3100:	r1 = r8
    3101:	call 34
; struct debug_msg msg = {
    3102:	*(u32 *)(r10 - 132) = r0
    3103:	r1 = 269496578
    3104:	*(u32 *)(r10 - 136) = r1
; cilium_dbg3(skb, DBG_CT_CREATED6, entry.rev_nat_index, ct_state->src_sec_id, 0);
    3105:	r7 &= 65535
; struct debug_msg msg = {
    3106:	*(u32 *)(r10 - 128) = r7
    3107:	r7 = 2
    3108:	*(u32 *)(r10 - 124) = r7
    3109:	r9 = 0
    3110:	*(u32 *)(r10 - 120) = r9
    3111:	r4 = r10
; entry.tx_packets = 1;
    3112:	r4 += -136
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3113:	r1 = r8
    3114:	r2 = 0 ll
    3116:	r3 = 4294967295 ll
    3118:	r5 = 20
    3119:	call 25
; entry.src_sec_id = ct_state->src_sec_id;
    3120:	*(u32 *)(r10 - 52) = r7
    3121:	r3 = r10
; entry.tx_packets = 1;
    3122:	r3 += -96
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    3123:	r1 = r6
    3124:	r7 = *(u64 *)(r10 - 200)
    3125:	r2 = r7
    3126:	r4 = 0
    3127:	call 2
    3128:	r0 <<= 32
    3129:	r0 s>>= 32
    3130:	if r0 s> -1 goto +89 <LBB13_308>
    3131:	r9 = 4294967141 ll
    3133:	goto -2949 <LBB13_37>

LBB13_302:
    3134:	r1 = 1
; skb->cb[CB_POLICY] = 1;
    3135:	r2 = *(u64 *)(r10 - 216)
    3136:	*(u32 *)(r2 + 56) = r1
    3137:	r2 = *(u64 *)(r10 - 320)
; if (ct_state.rev_nat_index) {
    3138:	r1 = r2
    3139:	r1 &= 65535
    3140:	if r1 == 0 goto +600 <LBB13_363>
    3141:	*(u16 *)(r10 - 24) = r2
    3142:	r6 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    3143:	r1 = r6
    3144:	call 34
; struct debug_msg msg = {
    3145:	*(u32 *)(r10 - 92) = r0
    3146:	r1 = 269490690
    3147:	*(u32 *)(r10 - 96) = r1
    3148:	r1 = *(u64 *)(r10 - 344)
    3149:	*(u32 *)(r10 - 88) = r1
    3150:	r1 = 0
    3151:	*(u32 *)(r10 - 84) = r1
    3152:	*(u32 *)(r10 - 80) = r1
    3153:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3154:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3155:	r1 = r6
    3156:	r2 = 0 ll
    3158:	r3 = 4294967295 ll
    3160:	r5 = 20
    3161:	call 25
    3162:	r2 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3163:	r2 += -24
; nat = map_lookup_elem(&cilium_lb6_reverse_nat, &index);
    3164:	r1 = 0 ll
    3166:	call 1
    3167:	r9 = 0
; if (nat == NULL)
    3168:	if r0 == 0 goto +560 <LBB13_359>
; cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);
    3169:	r7 = *(u8 *)(r0 + 17)
    3170:	r7 <<= 8
    3171:	r1 = *(u8 *)(r0 + 16)
    3172:	r7 |= r1
    3173:	r1 = *(u8 *)(r0 + 14)
    3174:	*(u64 *)(r10 - 224) = r1
    3175:	r9 = r0
    3176:	r6 = *(u8 *)(r9 + 15)
    3177:	r1 = *(u8 *)(r9 + 12)
    3178:	*(u64 *)(r10 - 240) = r1
    3179:	r8 = *(u8 *)(r9 + 13)
; uint32_t hash = get_hash_recalc(skb);
    3180:	r1 = *(u64 *)(r10 - 216)
    3181:	call 34
; struct debug_msg msg = {
    3182:	*(u32 *)(r10 - 92) = r0
    3183:	r1 = 269490946
    3184:	*(u32 *)(r10 - 96) = r1
    3185:	*(u32 *)(r10 - 84) = r7
    3186:	r1 = 0
    3187:	*(u32 *)(r10 - 80) = r1
; cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);
    3188:	r8 <<= 8
    3189:	r1 = *(u64 *)(r10 - 240)
    3190:	r8 |= r1
    3191:	r6 <<= 8
    3192:	r1 = *(u64 *)(r10 - 224)
    3193:	r6 |= r1
    3194:	r6 <<= 16
    3195:	r6 |= r8
    3196:	r1 = *(u64 *)(r10 - 216)
; struct debug_msg msg = {
    3197:	*(u32 *)(r10 - 88) = r6
    3198:	r4 = r10
; struct ipv6_ct_tuple *tuple, int flags,
    3199:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3200:	r2 = 0 ll
    3202:	r3 = 4294967295 ll
    3204:	r5 = 20
    3205:	call 25
; if (nat->port) {
    3206:	r1 = *(u8 *)(r9 + 16)
    3207:	r7 = r9
    3208:	r6 = *(u8 *)(r9 + 17)
    3209:	r6 <<= 8
    3210:	r6 |= r1
    3211:	if r6 == 0 goto +458 <LBB13_354>
    3212:	r9 = 4294967154 ll
    3214:	r1 = *(u64 *)(r10 - 200)
    3215:	r1 = *(u8 *)(r1 + 36)
; switch (nexthdr) {
    3216:	if r1 s> 16 goto +385 <LBB13_338>
    3217:	if r1 == 1 goto +441 <LBB13_350>
    3218:	if r1 == 6 goto +385 <LBB13_340>
    3219:	goto +440 <LBB13_351>

LBB13_308:
; struct ipv6_ct_tuple icmp_tuple = {
    3220:	r1 = 58
    3221:	*(u8 *)(r10 - 100) = r1
    3222:	*(u32 *)(r10 - 104) = r9
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    3223:	r1 = *(u16 *)(r10 - 60)
    3224:	r1 |= 16
; .flags = tuple->flags | TUPLE_F_RELATED,
    3225:	r2 = *(u8 *)(r7 + 37)
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    3226:	*(u16 *)(r10 - 60) = r1
; .flags = tuple->flags | TUPLE_F_RELATED,
    3227:	r2 |= 2
; struct ipv6_ct_tuple icmp_tuple = {
    3228:	*(u8 *)(r10 - 99) = r2
; dst->p1 = src->p1;
    3229:	r1 = *(u32 *)(r7 + 0)
    3230:	*(u32 *)(r10 - 136) = r1
; dst->p2 = src->p2;
    3231:	r1 = *(u32 *)(r7 + 4)
    3232:	*(u32 *)(r10 - 132) = r1
; dst->p3 = src->p3;
    3233:	r1 = *(u32 *)(r7 + 8)
    3234:	*(u32 *)(r10 - 128) = r1
; dst->p4 = src->p4;
    3235:	r1 = *(u32 *)(r7 + 12)
    3236:	*(u32 *)(r10 - 124) = r1
; dst->p1 = src->p1;
    3237:	r1 = *(u32 *)(r7 + 16)
    3238:	*(u32 *)(r10 - 120) = r1
; dst->p2 = src->p2;
    3239:	r1 = *(u32 *)(r7 + 20)
    3240:	*(u32 *)(r10 - 116) = r1
; dst->p3 = src->p3;
    3241:	r1 = *(u32 *)(r7 + 24)
    3242:	*(u32 *)(r10 - 112) = r1
; dst->p4 = src->p4;
    3243:	r1 = *(u32 *)(r7 + 28)
    3244:	*(u32 *)(r10 - 108) = r1
    3245:	r2 = r10
; struct ipv6_ct_tuple icmp_tuple = {
    3246:	r2 += -136
    3247:	r3 = r10
    3248:	r3 += -96
; if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
    3249:	r1 = r6
    3250:	r4 = 0
    3251:	call 2
    3252:	r1 = 128
    3253:	*(u64 *)(r10 - 328) = r1
    3254:	r0 <<= 32
; return DROP_CT_CREATE_FAILED;
    3255:	r9 = r0
    3256:	r9 s>>= 63
    3257:	r9 &= -155
; if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
    3258:	r0 s>>= 32
    3259:	r6 = r7
    3260:	r7 = *(u64 *)(r10 - 336)
    3261:	r4 = *(u64 *)(r10 - 248)
; if (IS_ERR(ret))
    3262:	if r0 s> -1 goto +1 <LBB13_309>
    3263:	goto -3079 <LBB13_37>

LBB13_309:
; return verdict > 0 && (dir == CT_NEW || dir == CT_ESTABLISHED);
    3264:	r1 = r4
    3265:	r1 <<= 32
    3266:	r1 s>>= 32
; if (redirect_to_proxy(verdict, forwarding_reason)) {
    3267:	if r1 s< 1 goto +473 <LBB13_363>
; union macaddr host_mac = HOST_IFINDEX_MAC;
    3268:	r1 = 95142176846542 ll
    3270:	*(u64 *)(r10 - 176) = r1
; BPF_V6(host_ip, HOST_IP);
    3271:	r1 = 61374
    3272:	*(u64 *)(r10 - 192) = r1
    3273:	r1 = -264973711704064 ll
    3275:	*(u64 *)(r10 - 184) = r1
; verdict, tuple->dport,
    3276:	r1 = *(u8 *)(r6 + 32)
    3277:	*(u64 *)(r10 - 208) = r1
    3278:	r8 = *(u8 *)(r6 + 33)
    3279:	r1 = *(u64 *)(r10 - 280)
    3280:	*(u32 *)(r10 - 32) = r1
    3281:	*(u64 *)(r10 - 40) = r7
    3282:	r1 = *(u64 *)(r10 - 240)
    3283:	*(u32 *)(r10 - 28) = r1
; .saddr = tuple->daddr,
    3284:	r3 = *(u8 *)(r6 + 13)
    3285:	r3 <<= 8
    3286:	r2 = *(u8 *)(r6 + 12)
    3287:	r3 |= r2
    3288:	r2 = *(u8 *)(r6 + 15)
    3289:	r2 <<= 8
    3290:	r1 = r4
    3291:	r4 = *(u8 *)(r6 + 14)
    3292:	r2 |= r4
    3293:	r5 = *(u8 *)(r6 + 9)
    3294:	r5 <<= 8
    3295:	r4 = *(u8 *)(r6 + 8)
    3296:	r5 |= r4
    3297:	r4 = *(u8 *)(r6 + 11)
    3298:	r4 <<= 8
    3299:	r0 = *(u8 *)(r6 + 10)
    3300:	r4 |= r0
    3301:	r4 <<= 16
    3302:	r4 |= r5
    3303:	r2 <<= 16
    3304:	r2 |= r3
    3305:	r0 = *(u8 *)(r6 + 1)
    3306:	r0 <<= 8
    3307:	r3 = *(u8 *)(r6 + 0)
    3308:	r0 |= r3
    3309:	r3 = *(u8 *)(r6 + 3)
    3310:	r3 <<= 8
    3311:	r5 = *(u8 *)(r6 + 2)
    3312:	r3 |= r5
    3313:	r5 = *(u8 *)(r6 + 6)
    3314:	*(u64 *)(r10 - 240) = r5
    3315:	r5 = *(u8 *)(r6 + 7)
    3316:	r9 = *(u8 *)(r6 + 4)
    3317:	r7 = r6
    3318:	r6 = *(u8 *)(r7 + 5)
    3319:	*(u64 *)(r10 - 248) = r1
; struct proxy6_tbl_key key = {
    3320:	*(u16 *)(r10 - 8) = r1
; verdict, tuple->dport,
    3321:	r8 <<= 8
    3322:	r1 = *(u64 *)(r10 - 208)
    3323:	r8 |= r1
; .saddr = tuple->daddr,
    3324:	r2 <<= 32
    3325:	r2 |= r4
    3326:	*(u64 *)(r10 - 16) = r2
    3327:	r3 <<= 16
    3328:	r3 |= r0
    3329:	r6 <<= 8
    3330:	r6 |= r9
    3331:	r5 <<= 8
    3332:	r1 = *(u64 *)(r10 - 240)
    3333:	r5 |= r1
    3334:	r5 <<= 16
    3335:	r5 |= r6
    3336:	r5 <<= 32
    3337:	r5 |= r3
    3338:	*(u64 *)(r10 - 24) = r5
; .sport = tuple->sport,
    3339:	r1 = *(u8 *)(r7 + 35)
    3340:	r1 <<= 8
    3341:	r2 = *(u8 *)(r7 + 34)
    3342:	r1 |= r2
; struct proxy6_tbl_key key = {
    3343:	*(u16 *)(r10 - 6) = r1
; .nexthdr = tuple->nexthdr,
    3344:	r1 = *(u8 *)(r7 + 36)
; struct proxy6_tbl_key key = {
    3345:	*(u8 *)(r10 - 4) = r1
    3346:	r6 = 0
    3347:	*(u8 *)(r10 - 3) = r6
; struct proxy6_tbl_value value = {
    3348:	*(u16 *)(r10 - 118) = r6
    3349:	r1 = 2
    3350:	*(u32 *)(r10 - 116) = r1
; .orig_daddr = old_ip,
    3351:	r1 = *(u64 *)(r10 - 32)
    3352:	*(u64 *)(r10 - 128) = r1
    3353:	r1 = *(u64 *)(r10 - 40)
    3354:	*(u64 *)(r10 - 136) = r1
; struct proxy6_tbl_value value = {
    3355:	*(u16 *)(r10 - 120) = r8
; return ktime_get_ns();
    3356:	call 5
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3357:	r0 /= 1000000000
; value->lifetime = bpf_ktime_get_sec() + PROXY_DEFAULT_LIFETIME;
    3358:	r0 += 720
    3359:	*(u32 *)(r10 - 112) = r0
    3360:	r7 = *(u64 *)(r10 - 328)
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    3361:	r7 <<= 32
    3362:	r7 >>= 32
; switch (obs_point) {
    3363:	if r7 == 0 goto +30 <LBB13_314>
    3364:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3365:	r9 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    3366:	call 34
; struct trace_notify msg = {
    3367:	*(u32 *)(r10 - 92) = r0
    3368:	r1 = 269484292
    3369:	*(u32 *)(r10 - 96) = r1
    3370:	r1 = 2
    3371:	*(u64 *)(r10 - 80) = r1
    3372:	r1 = *(u64 *)(r10 - 312)
    3373:	*(u8 *)(r10 - 70) = r1
    3374:	*(u16 *)(r10 - 72) = r6
    3375:	*(u8 *)(r10 - 69) = r6
    3376:	r1 = 1
    3377:	*(u32 *)(r10 - 68) = r1
    3378:	*(u32 *)(r10 - 88) = r9
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3379:	if r7 < r9 goto +1 <LBB13_313>
    3380:	r7 = r9

LBB13_313:
; struct trace_notify msg = {
    3381:	*(u32 *)(r10 - 84) = r7
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    3382:	r7 <<= 32
    3383:	r1 = 4294967295 ll
    3385:	r7 |= r1
    3386:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3387:	r4 += -96
; skb_event_output(skb, &cilium_events,
    3388:	r1 = *(u64 *)(r10 - 216)
    3389:	r2 = 0 ll
    3391:	r3 = r7
    3392:	r5 = 32
    3393:	call 25

LBB13_314:
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3394:	r1 = *(u64 *)(r10 - 304)
    3395:	r1 &= 65535
    3396:	r2 = *(u64 *)(r10 - 232)
    3397:	r2 += r1
    3398:	r4 = *(u64 *)(r10 - 248)
    3399:	*(u16 *)(r10 - 96) = r4
    3400:	r8 &= 65535
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    3401:	r4 &= 65535
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3402:	r5 = *(u64 *)(r10 - 272)
    3403:	r5 |= 2
    3404:	r5 &= 65535
    3405:	r7 = *(u64 *)(r10 - 216)
    3406:	r1 = r7
    3407:	r6 = r2
    3408:	r3 = r8
    3409:	*(u64 *)(r10 - 248) = r4
    3410:	call 11
    3411:	r0 <<= 32
    3412:	r0 s>>= 32
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    3413:	if r0 s> -1 goto +4 <LBB13_316>
    3414:	r9 = 4294967155 ll
    3416:	r8 = r7
    3417:	goto +86 <LBB13_323>

LBB13_316:
    3418:	r2 = *(u64 *)(r10 - 224)
; if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
    3419:	r2 += 16
    3420:	r3 = r10
    3421:	r3 += -96
    3422:	r1 = r7
    3423:	r4 = 2
    3424:	r5 = 0
    3425:	call 9
    3426:	r9 = 4294967155 ll
    3428:	r0 <<= 32
    3429:	r0 s>>= 32
    3430:	r8 = r7
; if (l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum, new_port, old_port) < 0)
    3431:	if r0 s< 0 goto +72 <LBB13_323>
    3432:	r3 = r10
; static inline int ipv6_store_daddr(struct __sk_buff *skb, __u8 *addr, int off)
    3433:	r3 += -192
; return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
    3434:	r1 = r8
    3435:	r2 = 38
    3436:	r4 = 16
    3437:	r5 = 0
    3438:	call 9
    3439:	r0 <<= 32
    3440:	r0 s>>= 32
; if (ipv6_store_daddr(skb, host_ip->addr, ETH_HLEN) > 0)
    3441:	if r0 s> 0 goto +62 <LBB13_323>
; if (csum->offset) {
    3442:	r1 = *(u64 *)(r10 - 304)
    3443:	if r1 == 0 goto +21 <LBB13_320>
    3444:	r1 = r10
; __be32 sum = csum_diff(old_ip.addr, 16, host_ip->addr, 16, 0);
    3445:	r1 += -40
    3446:	r3 = r10
    3447:	r3 += -192
    3448:	r2 = 16
    3449:	r4 = 16
    3450:	r5 = 0
    3451:	call 28
    3452:	r5 = *(u64 *)(r10 - 272)
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3453:	r5 |= 16
    3454:	r5 &= 65535
    3455:	r1 = r8
    3456:	r2 = r6
    3457:	r3 = 0
    3458:	r4 = r0
    3459:	call 11
    3460:	r9 = 4294967142 ll
    3462:	r0 <<= 32
    3463:	r0 s>>= 32
    3464:	if r0 s< 0 goto +39 <LBB13_323>

LBB13_320:
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3465:	r6 = *(u32 *)(r8 + 0)
; uint32_t hash = get_hash_recalc(skb);
    3466:	r1 = r8
    3467:	call 34
; struct debug_capture_msg msg = {
    3468:	*(u32 *)(r10 - 92) = r0
    3469:	r1 = 269486339
    3470:	*(u32 *)(r10 - 96) = r1
    3471:	r1 = *(u64 *)(r10 - 248)
    3472:	*(u32 *)(r10 - 80) = r1
    3473:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3474:	if r6 < 128 goto +1 <LBB13_322>
    3475:	r6 = 128

LBB13_322:
; struct debug_capture_msg msg = {
    3476:	*(u32 *)(r10 - 84) = r6
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    3477:	r6 <<= 32
    3478:	r1 = 4294967295 ll
    3480:	r6 |= r1
    3481:	r1 = 0
; struct debug_capture_msg msg = {
    3482:	*(u32 *)(r10 - 76) = r1
    3483:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3484:	r4 += -96
    3485:	r8 = *(u64 *)(r10 - 216)
; skb_event_output(skb, &cilium_events,
    3486:	r1 = r8
    3487:	r2 = 0 ll
    3489:	r3 = r6
    3490:	r5 = 24
    3491:	call 25
    3492:	r2 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3493:	r2 += -24
    3494:	r3 = r10
    3495:	r3 += -136
; if (map_update_elem(&cilium_proxy6, &key, &value, 0) < 0)
    3496:	r1 = 0 ll
    3498:	r4 = 0
    3499:	call 2
    3500:	r9 = r0
    3501:	r9 <<= 32
; return DROP_PROXYMAP_CREATE_FAILED;
    3502:	r9 s>>= 63
    3503:	r9 &= -161

LBB13_323:
; if (IS_ERR(ret))
    3504:	r1 = r9
    3505:	r1 <<= 32
    3506:	r1 >>= 32
    3507:	r2 = 1
    3508:	if r1 == 2 goto +1 <LBB13_325>
    3509:	r2 = 0

LBB13_325:
    3510:	r1 >>= 31
    3511:	r1 |= r2
    3512:	if r1 != 0 goto -3328 <LBB13_37>
; cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);
    3513:	r6 = *(u32 *)(r8 + 56)
; uint32_t hash = get_hash_recalc(skb);
    3514:	r1 = r8
    3515:	call 34
; struct debug_msg msg = {
    3516:	*(u32 *)(r10 - 92) = r0
    3517:	r1 = 269488898
    3518:	*(u32 *)(r10 - 96) = r1
    3519:	*(u32 *)(r10 - 88) = r6
    3520:	r1 = 0
    3521:	*(u32 *)(r10 - 84) = r1
    3522:	*(u32 *)(r10 - 80) = r1
    3523:	r4 = r10
; cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);
    3524:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3525:	r1 = r8
    3526:	r2 = 0 ll
    3528:	r3 = 4294967295 ll
    3530:	r5 = 20
    3531:	call 25
    3532:	r7 = 1
; hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
    3533:	r6 = r8
    3534:	r0 = *(u8 *)skb[21]
; if (hoplimit <= 1) {
    3535:	r1 = r0
    3536:	r1 &= 254
    3537:	r9 = 1
    3538:	if r1 == 0 goto +13 <LBB13_328>
; new_hl = hoplimit - 1;
    3539:	r0 += 255
    3540:	*(u8 *)(r10 - 96) = r0
    3541:	r3 = r10
    3542:	r3 += -96
; if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
    3543:	r1 = r8
    3544:	r2 = 21
    3545:	r4 = 1
    3546:	r5 = 1
    3547:	call 9
    3548:	r9 = r0
    3549:	r9 <<= 32
; return DROP_WRITE_ERROR;
    3550:	r9 s>>= 63
    3551:	r9 &= -141

LBB13_328:
; if (IS_ERR(ret))
    3552:	if r9 == 2 goto +1 <LBB13_330>
    3553:	r7 = 0

LBB13_330:
    3554:	r1 = 2147483648 ll
    3556:	r2 = r9
    3557:	r2 &= r1
    3558:	r2 >>= 31
    3559:	r2 |= r7
    3560:	if r2 != 0 goto +30 <LBB13_335>
; if (ret > 0) {
    3561:	if r9 s< 1 goto +6 <LBB13_333>
; skb->cb[1] = direction;
    3562:	r1 = 2
    3563:	*(u32 *)(r8 + 52) = r1
; skb->cb[0] = nh_off;
    3564:	r1 = 14
    3565:	*(u32 *)(r8 + 48) = r1
; tail_call(skb, &CALLS_MAP, index);
    3566:	r1 = r8
    3567:	goto +300 <LBB13_373>

LBB13_333:
    3568:	r3 = r10
; static inline int eth_store_saddr(struct __sk_buff *skb, __u8 *mac, int off)
    3569:	r3 += -144
; return skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
    3570:	r1 = r8
    3571:	r2 = 6
    3572:	r4 = 6
    3573:	r5 = 0
    3574:	call 9
    3575:	r9 = 4294967155 ll
    3577:	r0 <<= 32
    3578:	r0 s>>= 32
; if (smac && eth_store_saddr(skb, smac, 0) < 0)
    3579:	if r0 s< 0 goto -3395 <LBB13_37>
    3580:	r3 = r10
; static inline int eth_store_daddr(struct __sk_buff *skb, __u8 *mac, int off)
    3581:	r3 += -176
; return skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
    3582:	r1 = r8
    3583:	r2 = 0
    3584:	r4 = 6
    3585:	r5 = 0
    3586:	call 9
    3587:	r9 = r0
    3588:	r9 <<= 32
; return DROP_WRITE_ERROR;
    3589:	r9 s>>= 63
    3590:	r9 &= -141

LBB13_335:
; if (ret != TC_ACT_OK)
    3591:	if r9 != 0 goto -3407 <LBB13_37>
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3592:	r6 = *(u32 *)(r8 + 0)
; uint32_t hash = get_hash_recalc(skb);
    3593:	r1 = r8
    3594:	call 34
; struct debug_capture_msg msg = {
    3595:	*(u32 *)(r10 - 92) = r0
    3596:	r1 = 269485059
    3597:	*(u32 *)(r10 - 96) = r1
    3598:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3599:	if r6 < 128 goto +616 <LBB13_440>

LBB13_337:
    3600:	r6 = 128
    3601:	goto +614 <LBB13_440>

LBB13_338:
; switch (nexthdr) {
    3602:	if r1 == 58 goto +56 <LBB13_350>
    3603:	if r1 != 17 goto +56 <LBB13_351>

LBB13_340:
    3604:	r3 = r10
; static inline int l4_load_port(struct __sk_buff *skb, int off, __be16 *port)
    3605:	r3 += -136
; return skb_load_bytes(skb, off, port, sizeof(__be16));
    3606:	r1 = *(u64 *)(r10 - 216)
    3607:	r2 = *(u64 *)(r10 - 232)
    3608:	r4 = 2
    3609:	call 26
    3610:	r9 = r0
    3611:	r1 = r9
    3612:	r1 <<= 32
    3613:	r1 >>= 32
; if (IS_ERR(ret))
    3614:	r2 = 1
    3615:	if r1 == 2 goto +1 <LBB13_342>
    3616:	r2 = 0

LBB13_342:
    3617:	r1 >>= 31
    3618:	r1 |= r2
    3619:	if r1 != 0 goto +38 <LBB13_349>
; if (port != old_port) {
    3620:	r3 = *(u16 *)(r10 - 136)
    3621:	if r3 == r6 goto +37 <LBB13_350>
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3622:	r1 = *(u64 *)(r10 - 304)
    3623:	r1 &= 65535
    3624:	r2 = *(u64 *)(r10 - 232)
    3625:	r2 += r1
    3626:	*(u16 *)(r10 - 96) = r6
    3627:	r5 = *(u64 *)(r10 - 272)
    3628:	r5 |= 2
    3629:	r5 &= 65535
    3630:	r1 = *(u64 *)(r10 - 216)
    3631:	r4 = r6
    3632:	call 11
    3633:	r9 = 4294967142 ll
    3635:	r0 <<= 32
    3636:	r0 s>>= 32
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    3637:	if r0 s< 0 goto +11 <LBB13_346>
    3638:	r3 = r10
; if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
    3639:	r3 += -96
    3640:	r1 = *(u64 *)(r10 - 216)
    3641:	r2 = *(u64 *)(r10 - 232)
    3642:	r4 = 2
    3643:	r5 = 0
    3644:	call 9
    3645:	r9 = r0
    3646:	r9 <<= 32
; return DROP_WRITE_ERROR;
    3647:	r9 s>>= 63
    3648:	r9 &= -141

LBB13_346:
; if (IS_ERR(ret))
    3649:	r1 = r9
    3650:	r1 <<= 32
    3651:	r1 >>= 32
    3652:	r2 = 1
    3653:	if r1 == 2 goto +1 <LBB13_348>
    3654:	r2 = 0

LBB13_348:
    3655:	r1 >>= 31
    3656:	r1 |= r2
    3657:	if r1 == 0 goto +1 <LBB13_350>

LBB13_349:
    3658:	goto +1 <LBB13_351>

LBB13_350:
    3659:	r9 = 0

LBB13_351:
; if (IS_ERR(ret))
    3660:	r1 = r9
    3661:	r1 <<= 32
    3662:	r1 >>= 32
    3663:	r2 = 1
    3664:	if r1 == 2 goto +1 <LBB13_353>
    3665:	r2 = 0

LBB13_353:
    3666:	r1 >>= 31
    3667:	r1 |= r2
    3668:	r2 = *(u64 *)(r10 - 216)
    3669:	if r1 != 0 goto +59 <LBB13_359>

LBB13_354:
    3670:	r3 = r10
; static inline int ipv6_load_saddr(struct __sk_buff *skb, int off, union v6addr *dst)
    3671:	r3 += -96
; return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
    3672:	r1 = *(u64 *)(r10 - 216)
    3673:	r2 = 22
    3674:	r4 = 16
    3675:	call 26
    3676:	r9 = 4294967162 ll
    3678:	r0 <<= 32
    3679:	r0 s>>= 32
; if (ipv6_load_saddr(skb, ETH_HLEN, &old_saddr) < 0)
    3680:	if r0 s< 0 goto +48 <LBB13_359>
; dst->p1 = src->p1;
    3681:	r1 = *(u32 *)(r7 + 0)
    3682:	*(u32 *)(r10 - 136) = r1
; dst->p2 = src->p2;
    3683:	r1 = *(u32 *)(r7 + 4)
    3684:	*(u32 *)(r10 - 132) = r1
; dst->p3 = src->p3;
    3685:	r1 = *(u32 *)(r7 + 8)
    3686:	*(u32 *)(r10 - 128) = r1
; dst->p4 = src->p4;
    3687:	r1 = *(u32 *)(r7 + 12)
    3688:	*(u32 *)(r10 - 124) = r1
    3689:	r3 = r10
; dst->p1 = src->p1;
    3690:	r3 += -136
; return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, saddr), addr, 16, 0);
    3691:	r1 = *(u64 *)(r10 - 216)
    3692:	r2 = 22
    3693:	r4 = 16
    3694:	r5 = 0
    3695:	call 9
    3696:	r0 <<= 32
    3697:	r0 >>= 32
; if (IS_ERR(ret))
    3698:	r1 = 1
    3699:	if r0 == 2 goto +1 <LBB13_357>
    3700:	r1 = 0

LBB13_357:
    3701:	r0 >>= 31
    3702:	r0 |= r1
    3703:	r9 = 4294967155 ll
    3705:	if r0 != 0 goto +23 <LBB13_359>
    3706:	r1 = r10
; sum = csum_diff(old_saddr.addr, 16, new_saddr, 16, 0);
    3707:	r1 += -96
    3708:	r3 = r10
    3709:	r3 += -136
    3710:	r2 = 16
    3711:	r4 = 16
    3712:	r5 = 0
    3713:	call 28
    3714:	r1 = *(u64 *)(r10 - 304)
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3715:	r1 &= 65535
    3716:	r2 = *(u64 *)(r10 - 232)
    3717:	r2 += r1
    3718:	r5 = *(u64 *)(r10 - 272)
    3719:	r5 |= 16
    3720:	r5 &= 65535
    3721:	r1 = *(u64 *)(r10 - 216)
    3722:	r3 = 0
    3723:	r4 = r0
    3724:	call 11
    3725:	r9 = r0
    3726:	r9 <<= 32
; return DROP_CSUM_L4;
    3727:	r9 s>>= 63
    3728:	r9 &= -154

LBB13_359:
; if (IS_ERR(ret))
    3729:	r1 = r9
    3730:	r1 <<= 32
    3731:	r1 >>= 32
    3732:	r2 = 1
    3733:	if r1 == 2 goto +1 <LBB13_361>
    3734:	r2 = 0

LBB13_361:
    3735:	r1 >>= 31
    3736:	r1 |= r2
    3737:	if r1 != 0 goto -3553 <LBB13_37>
; skb->cb[CB_POLICY] = 1;
    3738:	r1 = 1
    3739:	r2 = *(u64 *)(r10 - 216)
    3740:	*(u32 *)(r2 + 56) = r1

LBB13_363:
    3741:	r2 = *(u64 *)(r10 - 216)
; void *data_end = (void *) (long) skb->data_end;
    3742:	r1 = *(u32 *)(r2 + 80)
; void *data = (void *) (long) skb->data;
    3743:	r6 = *(u32 *)(r2 + 76)
; if (data + ETH_HLEN + l3_len > data_end)
    3744:	r2 = r6
    3745:	r2 += 54
    3746:	r9 = 4294967162 ll
    3748:	if r2 > r1 goto -3564 <LBB13_37>
; key.ip6 = *((union v6addr *) &ip6->daddr);
    3749:	r1 = 2
    3750:	*(u32 *)(r10 - 80) = r1
    3751:	r2 = *(u8 *)(r6 + 47)
    3752:	r2 <<= 8
    3753:	r1 = *(u8 *)(r6 + 46)
    3754:	r2 |= r1
    3755:	r1 = *(u8 *)(r6 + 49)
    3756:	r1 <<= 8
    3757:	r3 = *(u8 *)(r6 + 48)
    3758:	r1 |= r3
    3759:	r1 <<= 16
    3760:	r1 |= r2
    3761:	r3 = *(u8 *)(r6 + 51)
    3762:	r3 <<= 8
    3763:	r2 = *(u8 *)(r6 + 50)
    3764:	r3 |= r2
    3765:	r2 = *(u8 *)(r6 + 53)
    3766:	r2 <<= 8
    3767:	r4 = *(u8 *)(r6 + 52)
    3768:	r2 |= r4
    3769:	r2 <<= 16
    3770:	r2 |= r3
    3771:	r2 <<= 32
    3772:	r2 |= r1
    3773:	r3 = *(u8 *)(r6 + 39)
    3774:	r3 <<= 8
    3775:	r1 = *(u8 *)(r6 + 38)
    3776:	r3 |= r1
    3777:	r1 = *(u8 *)(r6 + 41)
    3778:	r1 <<= 8
    3779:	r4 = *(u8 *)(r6 + 40)
    3780:	r1 |= r4
    3781:	*(u64 *)(r10 - 88) = r2
    3782:	r1 <<= 16
    3783:	r1 |= r3
    3784:	r2 = *(u8 *)(r6 + 43)
    3785:	r2 <<= 8
    3786:	r3 = *(u8 *)(r6 + 42)
    3787:	r2 |= r3
    3788:	r3 = *(u8 *)(r6 + 45)
    3789:	r3 <<= 8
    3790:	r4 = *(u8 *)(r6 + 44)
    3791:	r3 |= r4
    3792:	r3 <<= 16
    3793:	r3 |= r2
    3794:	r3 <<= 32
    3795:	r3 |= r1
    3796:	*(u64 *)(r10 - 96) = r3
    3797:	r2 = r10
    3798:	r2 += -96
; return map_lookup_elem(&cilium_lxc, &key);
    3799:	r1 = 0 ll
    3801:	call 1
    3802:	r8 = r0
; if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
    3803:	if r8 == 0 goto +71 <LBB13_375>
; if (ep->flags & ENDPOINT_F_HOST) {
    3804:	r1 = *(u8 *)(r8 + 8)
    3805:	r1 &= 1
    3806:	if r1 != 0 goto +128 <LBB13_379>
; skb->cb[CB_POLICY] = 0;
    3807:	r6 = 0
    3808:	r9 = *(u64 *)(r10 - 216)
    3809:	*(u32 *)(r9 + 56) = r6
; cilium_dbg(skb, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);
    3810:	r7 = *(u16 *)(r8 + 6)
; uint32_t hash = get_hash_recalc(skb);
    3811:	r1 = r9
    3812:	call 34
; struct debug_msg msg = {
    3813:	*(u32 *)(r10 - 92) = r0
    3814:	r1 = 269484546
    3815:	*(u32 *)(r10 - 96) = r1
    3816:	*(u32 *)(r10 - 88) = r7
    3817:	r1 = 2
    3818:	*(u32 *)(r10 - 84) = r1
    3819:	*(u32 *)(r10 - 80) = r6
    3820:	r4 = r10
; skb->cb[CB_POLICY] = 0;
    3821:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3822:	r1 = r9
    3823:	r2 = 0 ll
    3825:	r3 = 4294967295 ll
    3827:	r5 = 20
    3828:	call 25
; mac_t lxc_mac = ep->mac;
    3829:	r1 = *(u64 *)(r8 + 16)
    3830:	*(u64 *)(r10 - 24) = r1
; mac_t router_mac = ep->node_mac;
    3831:	r1 = *(u64 *)(r8 + 24)
    3832:	*(u64 *)(r10 - 40) = r1
    3833:	r7 = 1
; hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
    3834:	r6 = r9
    3835:	r0 = *(u8 *)skb[21]
; if (hoplimit <= 1) {
    3836:	r1 = r0
    3837:	r1 &= 254
    3838:	r9 = 1
    3839:	if r1 == 0 goto +13 <LBB13_368>
; new_hl = hoplimit - 1;
    3840:	r0 += 255
    3841:	*(u8 *)(r10 - 96) = r0
    3842:	r3 = r10
    3843:	r3 += -96
; if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
    3844:	r1 = *(u64 *)(r10 - 216)
    3845:	r2 = 21
    3846:	r4 = 1
    3847:	r5 = 1
    3848:	call 9
    3849:	r9 = r0
    3850:	r9 <<= 32
; return DROP_WRITE_ERROR;
    3851:	r9 s>>= 63
    3852:	r9 &= -141

LBB13_368:
; if (IS_ERR(ret))
    3853:	if r9 == 2 goto +1 <LBB13_370>
    3854:	r7 = 0

LBB13_370:
    3855:	r1 = 2147483648 ll
    3857:	r2 = r9
    3858:	r2 &= r1
    3859:	r2 >>= 31
    3860:	r2 |= r7
    3861:	if r2 != 0 goto +150 <LBB13_391>
; if (ret > 0) {
    3862:	if r9 s< 1 goto +126 <LBB13_389>

LBB13_372:
; skb->cb[1] = direction;
    3863:	r2 = 2
    3864:	r1 = *(u64 *)(r10 - 216)
    3865:	*(u32 *)(r1 + 52) = r2
; skb->cb[0] = nh_off;
    3866:	r2 = 14
    3867:	*(u32 *)(r1 + 48) = r2

LBB13_373:
; tail_call(skb, &CALLS_MAP, index);
    3868:	r2 = 0 ll
    3870:	r3 = 5

LBB13_374:
    3871:	call 12
    3872:	r9 = 4294967156 ll
    3874:	goto -3690 <LBB13_37>

LBB13_375:
    3875:	r9 = *(u64 *)(r10 - 352)
; if (tunnel_endpoint) {
    3876:	r1 = r9
    3877:	r1 <<= 32
    3878:	r1 >>= 32
    3879:	if r1 == 0 goto +466 <LBB13_386>
    3880:	r6 = 0
; struct bpf_tunnel_key key = {};
    3881:	*(u32 *)(r10 - 112) = r6
    3882:	*(u64 *)(r10 - 120) = r6
    3883:	*(u64 *)(r10 - 128) = r6
; key.tunnel_id = seclabel;
    3884:	r7 = 2
    3885:	*(u32 *)(r10 - 136) = r7
; node_id = bpf_htonl(tunnel_endpoint);
    3886:	r9 = be32 r9
; key.remote_ipv4 = node_id;
    3887:	*(u32 *)(r10 - 132) = r9
    3888:	r8 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    3889:	r1 = r8
    3890:	call 34
; struct debug_msg msg = {
    3891:	*(u32 *)(r10 - 92) = r0
    3892:	r1 = 269484802
    3893:	*(u32 *)(r10 - 96) = r1
    3894:	*(u32 *)(r10 - 88) = r9
    3895:	*(u32 *)(r10 - 84) = r7
    3896:	*(u32 *)(r10 - 80) = r6
    3897:	r4 = r10
; __u32 seclabel, __u32 monitor)
    3898:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3899:	r1 = r8
    3900:	r2 = 0 ll
    3902:	r3 = 4294967295 ll
    3904:	r5 = 20
    3905:	call 25
    3906:	r2 = r10
; __u32 seclabel, __u32 monitor)
    3907:	r2 += -136
; ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
    3908:	r1 = r8
    3909:	r3 = 28
    3910:	r4 = 0
    3911:	call 21
    3912:	r9 = 4294967155 ll
    3914:	r0 <<= 32
    3915:	r0 s>>= 32
; if (unlikely(ret < 0))
    3916:	if r0 s< 0 goto -3732 <LBB13_37>
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    3917:	r7 = *(u32 *)(r8 + 0)
; struct metrics_value *entry, newEntry = {};
    3918:	*(u64 *)(r10 - 88) = r6
    3919:	*(u64 *)(r10 - 96) = r6
; struct metrics_key key = {};
    3920:	r1 = 512
    3921:	*(u64 *)(r10 - 24) = r1
    3922:	r2 = r10
; send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
    3923:	r2 += -24
; if ((entry = map_lookup_elem(&cilium_metrics, &key))) {
    3924:	r1 = 0 ll
    3926:	call 1
    3927:	if r0 == 0 goto +171 <LBB13_399>
; entry->count += 1;
    3928:	r1 = *(u64 *)(r0 + 0)
    3929:	r1 += 1
    3930:	*(u64 *)(r0 + 0) = r1
; entry->bytes += (__u64)bytes;
    3931:	r1 = *(u64 *)(r0 + 8)
    3932:	r1 += r7
    3933:	*(u64 *)(r0 + 8) = r1
    3934:	goto +175 <LBB13_400>

LBB13_379:
; union macaddr host_mac = HOST_IFINDEX_MAC;
    3935:	r1 = 95142176846542 ll
    3937:	*(u64 *)(r10 - 24) = r1
    3938:	r8 = *(u64 *)(r10 - 216)
; return skb->cb[CB_POLICY];
    3939:	r6 = *(u32 *)(r8 + 56)
; uint32_t hash = get_hash_recalc(skb);
    3940:	r1 = r8
    3941:	call 34
; struct debug_msg msg = {
    3942:	*(u32 *)(r10 - 92) = r0
    3943:	r1 = 269488898
    3944:	*(u32 *)(r10 - 96) = r1
    3945:	*(u32 *)(r10 - 88) = r6
    3946:	r1 = 0
    3947:	*(u32 *)(r10 - 84) = r1
    3948:	*(u32 *)(r10 - 80) = r1
    3949:	r4 = r10
; union macaddr host_mac = HOST_IFINDEX_MAC;
    3950:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3951:	r1 = r8
    3952:	r2 = 0 ll
    3954:	r3 = 4294967295 ll
    3956:	r5 = 20
    3957:	call 25
    3958:	r7 = 1
; hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
    3959:	r6 = r8
    3960:	r0 = *(u8 *)skb[21]
; if (hoplimit <= 1) {
    3961:	r1 = r0
    3962:	r1 &= 254
    3963:	r9 = 1
    3964:	if r1 == 0 goto +13 <LBB13_381>
; new_hl = hoplimit - 1;
    3965:	r0 += 255
    3966:	*(u8 *)(r10 - 96) = r0
    3967:	r3 = r10
    3968:	r3 += -96
; if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
    3969:	r1 = r8
    3970:	r2 = 21
    3971:	r4 = 1
    3972:	r5 = 1
    3973:	call 9
    3974:	r9 = r0
    3975:	r9 <<= 32
; return DROP_WRITE_ERROR;
    3976:	r9 s>>= 63
    3977:	r9 &= -141

LBB13_381:
; if (IS_ERR(ret))
    3978:	if r9 == 2 goto +1 <LBB13_383>
    3979:	r7 = 0

LBB13_383:
    3980:	r1 = 2147483648 ll
    3982:	r2 = r9
    3983:	r2 &= r1
    3984:	r2 >>= 31
    3985:	r2 |= r7
    3986:	if r2 != 0 goto +91 <LBB13_396>
; if (ret > 0) {
    3987:	if r9 s< 1 goto +67 <LBB13_394>
    3988:	goto -126 <LBB13_372>

LBB13_389:
    3989:	r3 = r10
; static inline int eth_store_saddr(struct __sk_buff *skb, __u8 *mac, int off)
    3990:	r3 += -40
; return skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
    3991:	r1 = *(u64 *)(r10 - 216)
    3992:	r2 = 6
    3993:	r4 = 6
    3994:	r5 = 0
    3995:	call 9
    3996:	r9 = 4294967155 ll
    3998:	r0 <<= 32
    3999:	r0 s>>= 32
; if (smac && eth_store_saddr(skb, smac, 0) < 0)
    4000:	if r0 s< 0 goto -3816 <LBB13_37>
    4001:	r3 = r10
; static inline int eth_store_daddr(struct __sk_buff *skb, __u8 *mac, int off)
    4002:	r3 += -24
; return skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
    4003:	r1 = *(u64 *)(r10 - 216)
    4004:	r2 = 0
    4005:	r4 = 6
    4006:	r5 = 0
    4007:	call 9
    4008:	r9 = r0
    4009:	r9 <<= 32
; return DROP_WRITE_ERROR;
    4010:	r9 s>>= 63
    4011:	r9 &= -141

LBB13_391:
; if (ret != TC_ACT_OK)
    4012:	if r9 != 0 goto -3828 <LBB13_37>
; cilium_dbg(skb, DBG_LXC_FOUND, ep->ifindex, 0);
    4013:	r6 = *(u32 *)(r8 + 0)
    4014:	r9 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    4015:	r1 = r9
    4016:	call 34
; struct debug_msg msg = {
    4017:	*(u32 *)(r10 - 92) = r0
    4018:	r1 = 269485058
    4019:	*(u32 *)(r10 - 96) = r1
    4020:	*(u32 *)(r10 - 88) = r6
    4021:	r7 = 0
    4022:	*(u32 *)(r10 - 84) = r7
    4023:	*(u32 *)(r10 - 80) = r7
    4024:	r4 = r10
; cilium_dbg(skb, DBG_LXC_FOUND, ep->ifindex, 0);
    4025:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4026:	r1 = r9
    4027:	r2 = 0 ll
    4029:	r3 = 4294967295 ll
    4031:	r5 = 20
    4032:	call 25
; skb->cb[CB_SRC_LABEL] = seclabel;
    4033:	r1 = 2
    4034:	*(u32 *)(r9 + 48) = r1
; skb->cb[CB_IFINDEX] = ep->ifindex;
    4035:	r1 = *(u32 *)(r8 + 0)
    4036:	*(u32 *)(r9 + 52) = r1
; update_metrics(skb->len, direction, REASON_FORWARDED);
    4037:	r6 = *(u32 *)(r9 + 0)
; struct metrics_value *entry, newEntry = {};
    4038:	*(u64 *)(r10 - 88) = r7
    4039:	*(u64 *)(r10 - 96) = r7
; struct metrics_key key = {};
    4040:	r1 = 512
    4041:	*(u64 *)(r10 - 136) = r1
    4042:	r2 = r10
; cilium_dbg(skb, DBG_LXC_FOUND, ep->ifindex, 0);
    4043:	r2 += -136
; if ((entry = map_lookup_elem(&cilium_metrics, &key))) {
    4044:	r1 = 0 ll
    4046:	call 1
    4047:	if r0 == 0 goto +95 <LBB13_431>
; entry->count += 1;
    4048:	r1 = *(u64 *)(r0 + 0)
    4049:	r1 += 1
    4050:	*(u64 *)(r0 + 0) = r1
; entry->bytes += (__u64)bytes;
    4051:	r1 = *(u64 *)(r0 + 8)
    4052:	r1 += r6
    4053:	*(u64 *)(r0 + 8) = r1
    4054:	goto +99 <LBB13_432>

LBB13_394:
    4055:	r3 = r10
; static inline int eth_store_saddr(struct __sk_buff *skb, __u8 *mac, int off)
    4056:	r3 += -144
; return skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
    4057:	r1 = *(u64 *)(r10 - 216)
    4058:	r2 = 6
    4059:	r4 = 6
    4060:	r5 = 0
    4061:	call 9
    4062:	r9 = 4294967155 ll
    4064:	r0 <<= 32
    4065:	r0 s>>= 32
; if (smac && eth_store_saddr(skb, smac, 0) < 0)
    4066:	if r0 s< 0 goto -3882 <LBB13_37>
    4067:	r3 = r10
; static inline int eth_store_daddr(struct __sk_buff *skb, __u8 *mac, int off)
    4068:	r3 += -24
; return skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
    4069:	r1 = *(u64 *)(r10 - 216)
    4070:	r2 = 0
    4071:	r4 = 6
    4072:	r5 = 0
    4073:	call 9
    4074:	r9 = r0
    4075:	r9 <<= 32
; return DROP_WRITE_ERROR;
    4076:	r9 s>>= 63
    4077:	r9 &= -141

LBB13_396:
; if (ret != TC_ACT_OK)
    4078:	if r9 != 0 goto -3894 <LBB13_37>
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    4079:	r1 = *(u64 *)(r10 - 216)
    4080:	r6 = *(u32 *)(r1 + 0)
    4081:	r1 = 0
; struct metrics_value *entry, newEntry = {};
    4082:	*(u64 *)(r10 - 88) = r1
    4083:	*(u64 *)(r10 - 96) = r1
; struct metrics_key key = {};
    4084:	r1 = 512
    4085:	*(u64 *)(r10 - 136) = r1
    4086:	r2 = r10
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    4087:	r2 += -136
; if ((entry = map_lookup_elem(&cilium_metrics, &key))) {
    4088:	r1 = 0 ll
    4090:	call 1
    4091:	if r0 == 0 goto +67 <LBB13_433>
; entry->count += 1;
    4092:	r1 = *(u64 *)(r0 + 0)
    4093:	r1 += 1
    4094:	*(u64 *)(r0 + 0) = r1
; entry->bytes += (__u64)bytes;
    4095:	r1 = *(u64 *)(r0 + 8)
    4096:	r1 += r6
    4097:	*(u64 *)(r0 + 8) = r1
    4098:	goto +71 <LBB13_434>

LBB13_399:
; newEntry.bytes = (__u64)bytes;
    4099:	*(u64 *)(r10 - 88) = r7
; newEntry.count = 1;
    4100:	r1 = 1
    4101:	*(u64 *)(r10 - 96) = r1
    4102:	r2 = r10
; newEntry.bytes = (__u64)bytes;
    4103:	r2 += -24
    4104:	r3 = r10
    4105:	r3 += -96
; map_update_elem(&cilium_metrics, &key, &newEntry, 0);
    4106:	r1 = 0 ll
    4108:	r4 = 0
    4109:	call 2

LBB13_400:
    4110:	r1 = *(u64 *)(r10 - 328)
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    4111:	r1 <<= 32
    4112:	r1 >>= 32
    4113:	r7 = r1
; switch (obs_point) {
    4114:	if r1 == 0 goto +116 <LBB13_442>
    4115:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4116:	r6 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4117:	call 34
    4118:	r1 = 0
; struct trace_notify msg = {
    4119:	*(u32 *)(r10 - 72) = r1
    4120:	*(u32 *)(r10 - 92) = r0
    4121:	r1 = 269485060
    4122:	*(u32 *)(r10 - 96) = r1
    4123:	r1 = 2
    4124:	*(u64 *)(r10 - 80) = r1
    4125:	r1 = 1
    4126:	*(u32 *)(r10 - 68) = r1
    4127:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4128:	if r7 < r6 goto +1 <LBB13_403>
    4129:	r7 = r6

LBB13_403:
    4130:	r3 = r7
; struct trace_notify msg = {
    4131:	*(u32 *)(r10 - 84) = r3
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4132:	r3 <<= 32
    4133:	r1 = 4294967295 ll
    4135:	r3 |= r1
    4136:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4137:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4138:	r1 = *(u64 *)(r10 - 216)
    4139:	r2 = 0 ll
    4141:	r5 = 32
    4142:	goto +87 <LBB13_441>

LBB13_431:
; newEntry.bytes = (__u64)bytes;
    4143:	*(u64 *)(r10 - 88) = r6
; newEntry.count = 1;
    4144:	r1 = 1
    4145:	*(u64 *)(r10 - 96) = r1
    4146:	r2 = r10
; newEntry.bytes = (__u64)bytes;
    4147:	r2 += -136
    4148:	r3 = r10
    4149:	r3 += -96
; map_update_elem(&cilium_metrics, &key, &newEntry, 0);
    4150:	r1 = 0 ll
    4152:	r4 = 0
    4153:	call 2

LBB13_432:
; tail_call(skb, &cilium_policy, ep->lxc_id);
    4154:	r3 = *(u16 *)(r8 + 6)
    4155:	r1 = *(u64 *)(r10 - 216)
    4156:	r2 = 0 ll
    4158:	goto -288 <LBB13_374>

LBB13_433:
; newEntry.bytes = (__u64)bytes;
    4159:	*(u64 *)(r10 - 88) = r6
; newEntry.count = 1;
    4160:	r1 = 1
    4161:	*(u64 *)(r10 - 96) = r1
    4162:	r2 = r10
; newEntry.bytes = (__u64)bytes;
    4163:	r2 += -136
    4164:	r3 = r10
    4165:	r3 += -96
; map_update_elem(&cilium_metrics, &key, &newEntry, 0);
    4166:	r1 = 0 ll
    4168:	r4 = 0
    4169:	call 2

LBB13_434:
    4170:	r1 = *(u64 *)(r10 - 328)
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    4171:	r1 <<= 32
    4172:	r1 >>= 32
    4173:	r7 = r1
; switch (obs_point) {
    4174:	if r1 == 0 goto +32 <LBB13_438>
    4175:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4176:	r6 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4177:	call 34
; struct trace_notify msg = {
    4178:	*(u32 *)(r10 - 92) = r0
    4179:	r1 = 269484548
    4180:	*(u32 *)(r10 - 96) = r1
    4181:	r1 = 4294967298 ll
    4183:	*(u64 *)(r10 - 80) = r1
    4184:	r1 = *(u64 *)(r10 - 312)
    4185:	*(u8 *)(r10 - 70) = r1
    4186:	r1 = 0
    4187:	*(u16 *)(r10 - 72) = r1
    4188:	*(u8 *)(r10 - 69) = r1
    4189:	r1 = 1
    4190:	*(u32 *)(r10 - 68) = r1
    4191:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4192:	if r7 < r6 goto +1 <LBB13_437>
    4193:	r7 = r6

LBB13_437:
    4194:	r3 = r7
; struct trace_notify msg = {
    4195:	*(u32 *)(r10 - 84) = r3
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4196:	r3 <<= 32
    4197:	r1 = 4294967295 ll
    4199:	r3 |= r1
    4200:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4201:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4202:	r1 = *(u64 *)(r10 - 216)
    4203:	r2 = 0 ll
    4205:	r5 = 32
    4206:	call 25

LBB13_438:
    4207:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4208:	r6 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4209:	call 34
; struct debug_capture_msg msg = {
    4210:	*(u32 *)(r10 - 92) = r0
    4211:	r1 = 269485059
    4212:	*(u32 *)(r10 - 96) = r1
    4213:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4214:	if r6 < 128 goto +1 <LBB13_440>
    4215:	goto -616 <LBB13_337>

LBB13_440:
; struct debug_capture_msg msg = {
    4216:	*(u32 *)(r10 - 84) = r6
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4217:	r6 <<= 32
    4218:	r1 = 4294967295 ll
    4220:	r6 |= r1
    4221:	r1 = 1
; struct debug_capture_msg msg = {
    4222:	*(u64 *)(r10 - 80) = r1
    4223:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4224:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4225:	r1 = *(u64 *)(r10 - 216)
    4226:	r2 = 0 ll
    4228:	r3 = r6
    4229:	r5 = 24

LBB13_441:
    4230:	call 25

LBB13_442:
    4231:	r1 = 1
    4232:	r2 = 0
    4233:	call 23
    4234:	r9 = r0
    4235:	goto -4051 <LBB13_37>

LBB13_452:
    4236:	r6 = *(u64 *)(r10 - 288)
    4237:	*(u64 *)(r10 - 296) = r7
    4238:	r1 = 0
; key.protocol = 0;
    4239:	*(u8 *)(r10 - 130) = r1
; key.dport = 0;
    4240:	*(u16 *)(r10 - 132) = r1
    4241:	r2 = r10
; key.protocol = 0;
    4242:	r2 += -136
; policy = map_lookup_elem(map, &key);
    4243:	r1 = 0 ll
    4245:	call 1
; if (likely(policy)) {
    4246:	if r0 == 0 goto +8 <LBB13_454>
; __sync_fetch_and_add(&policy->packets, 1);
    4247:	r1 = 1
    4248:	lock *(u64 *)(r0 + 8) += r1
    4249:	r1 = *(u64 *)(r10 - 216)
; __sync_fetch_and_add(&policy->bytes, skb->len);
    4250:	r1 = *(u32 *)(r1 + 0)
    4251:	lock *(u64 *)(r0 + 16) += r1
    4252:	r4 = 0
    4253:	r7 = *(u64 *)(r10 - 336)
    4254:	goto -1209 <LBB13_290>

LBB13_454:
; key.dport = dport;
    4255:	*(u16 *)(r10 - 132) = r9
    4256:	r1 = 0
; key.sec_label = 0;
    4257:	*(u32 *)(r10 - 136) = r1
; key.protocol = proto;
    4258:	*(u8 *)(r10 - 130) = r6
    4259:	r2 = r10
; key.dport = dport;
    4260:	r2 += -136
; policy = map_lookup_elem(map, &key);
    4261:	r1 = 0 ll
    4263:	call 1
    4264:	r6 = r0
; if (likely(policy)) {
    4265:	if r6 == 0 goto +5 <LBB13_456>
; __sync_fetch_and_add(&policy->packets, 1);
    4266:	r1 = 1
    4267:	lock *(u64 *)(r6 + 8) += r1
    4268:	r1 = *(u64 *)(r10 - 216)
; __sync_fetch_and_add(&policy->bytes, skb->len);
    4269:	r1 = *(u32 *)(r1 + 0)
    4270:	goto -1228 <LBB13_289>

LBB13_456:
    4271:	r1 = *(u64 *)(r10 - 216)
; if (skb->cb[CB_POLICY])
    4272:	r1 = *(u32 *)(r1 + 56)
    4273:	r7 = *(u64 *)(r10 - 336)
    4274:	r4 = 0
    4275:	if r1 == 0 goto +1 <LBB13_457>
    4276:	goto -1231 <LBB13_290>

LBB13_457:
    4277:	r6 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    4278:	r1 = r6
    4279:	call 34
; struct debug_msg msg = {
    4280:	*(u32 *)(r10 - 92) = r0
    4281:	r1 = 269485314
    4282:	*(u32 *)(r10 - 96) = r1
    4283:	r1 = 2
    4284:	*(u32 *)(r10 - 88) = r1
    4285:	r1 = *(u64 *)(r10 - 296)
    4286:	*(u32 *)(r10 - 84) = r1
    4287:	r1 = 0
    4288:	*(u32 *)(r10 - 80) = r1
    4289:	r4 = r10
; int ret = __policy_can_access(&POLICY_MAP, skb, identity, dport, proto,
    4290:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4291:	r1 = r6
    4292:	r2 = 0 ll
    4294:	r3 = 4294967295 ll
    4296:	r5 = 20
    4297:	call 25
    4298:	r4 = 4294967163 ll
; if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
    4300:	r1 = *(u64 *)(r10 - 312)
    4301:	r1 |= 1
    4302:	r6 = *(u64 *)(r10 - 200)
    4303:	if r1 == 3 goto -1257 <LBB13_291>
    4304:	r9 = 4294967163 ll
; if (ret == CT_ESTABLISHED)
    4306:	r1 = *(u64 *)(r10 - 312)
    4307:	if r1 != 1 goto -4123 <LBB13_37>
; if (tuple->nexthdr == IPPROTO_TCP) {
    4308:	r2 = *(u8 *)(r6 + 36)
; ct_delete6(get_ct_map6(tuple), tuple, skb);
    4309:	r1 = 0 ll
    4311:	if r2 == 6 goto +2 <LBB13_461>
    4312:	r1 = 0 ll

LBB13_461:
; if ((err = map_delete_elem(map, tuple)) < 0)
    4314:	r2 = *(u64 *)(r10 - 200)
    4315:	call 3
    4316:	r6 = r0
    4317:	r6 <<= 32
    4318:	r6 s>>= 32
    4319:	r7 = *(u64 *)(r10 - 216)
    4320:	if r6 s> -1 goto -4136 <LBB13_37>
; uint32_t hash = get_hash_recalc(skb);
    4321:	r1 = r7
    4322:	call 34
; struct debug_msg msg = {
    4323:	*(u32 *)(r10 - 92) = r0
    4324:	r1 = 269488642
    4325:	*(u32 *)(r10 - 96) = r1
    4326:	r1 = 3
    4327:	*(u32 *)(r10 - 88) = r1
    4328:	*(u32 *)(r10 - 84) = r6
    4329:	r1 = 0
    4330:	*(u32 *)(r10 - 80) = r1
    4331:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    4332:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4333:	r1 = r7
    4334:	r2 = 0 ll
    4336:	r3 = 4294967295 ll
    4338:	r5 = 20
    4339:	goto +335 <LBB13_451>

LBB13_463:
    4340:	r6 = 2
    4341:	r1 = *(u64 *)(r10 - 208)
; *dstID = WORLD_ID;
    4342:	*(u32 *)(r1 + 0) = r6
    4343:	r9 = r1
    4344:	r7 = 53
    4345:	goto -1381 <LBB13_285>

LBB13_386:
; key.ip6.p1 = daddr->p1;
    4346:	r1 = *(u32 *)(r6 + 38)
    4347:	*(u32 *)(r10 - 24) = r1
; key.ip6.p2 = daddr->p2;
    4348:	r1 = *(u32 *)(r6 + 42)
    4349:	*(u32 *)(r10 - 20) = r1
; key.ip6.p3 = daddr->p3;
    4350:	r1 = *(u32 *)(r6 + 46)
    4351:	r8 = 0
; key.ip6.p4 = 0;
    4352:	*(u32 *)(r10 - 12) = r8
; key.ip6.p3 = daddr->p3;
    4353:	*(u32 *)(r10 - 16) = r1
; key.family = ENDPOINT_KEY_IPV6;
    4354:	r1 = 2
    4355:	*(u8 *)(r10 - 8) = r1
    4356:	r2 = r10
; key.ip6.p1 = daddr->p1;
    4357:	r2 += -24
; if ((tunnel = map_lookup_elem(&cilium_tunnel_map, k)) == NULL) {
    4358:	r1 = 0 ll
    4360:	call 1
    4361:	if r0 == 0 goto +122 <LBB13_413>
; return encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
    4362:	r1 = *(u8 *)(r0 + 1)
    4363:	r1 <<= 8
    4364:	r2 = *(u8 *)(r0 + 0)
    4365:	r1 |= r2
    4366:	r2 = *(u8 *)(r0 + 2)
    4367:	r7 = *(u8 *)(r0 + 3)
    4368:	r7 <<= 8
    4369:	r7 |= r2
    4370:	r7 <<= 16
    4371:	r7 |= r1
; struct bpf_tunnel_key key = {};
    4372:	*(u32 *)(r10 - 112) = r8
    4373:	*(u64 *)(r10 - 120) = r8
    4374:	*(u64 *)(r10 - 128) = r8
; key.family = ENDPOINT_KEY_IPV6;
    4375:	r1 = 2
; key.tunnel_id = seclabel;
    4376:	*(u32 *)(r10 - 136) = r1
; node_id = bpf_htonl(tunnel_endpoint);
    4377:	r7 = be32 r7
; key.remote_ipv4 = node_id;
    4378:	*(u32 *)(r10 - 132) = r7
    4379:	r9 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    4380:	r1 = r9
    4381:	call 34
; struct debug_msg msg = {
    4382:	*(u32 *)(r10 - 92) = r0
    4383:	r1 = 269484802
    4384:	*(u32 *)(r10 - 96) = r1
    4385:	*(u32 *)(r10 - 88) = r7
    4386:	r1 = 2
    4387:	*(u32 *)(r10 - 84) = r1
    4388:	*(u32 *)(r10 - 80) = r8
    4389:	r4 = r10
; return encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
    4390:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4391:	r1 = r9
    4392:	r2 = 0 ll
    4394:	r3 = 4294967295 ll
    4396:	r5 = 20
    4397:	call 25
    4398:	r2 = r10
; return encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
    4399:	r2 += -136
; ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
    4400:	r1 = r9
    4401:	r3 = 28
    4402:	r4 = 0
    4403:	call 21
    4404:	r0 <<= 32
    4405:	r0 s>>= 32
; if (unlikely(ret < 0))
    4406:	if r0 s> -1 goto +3 <LBB13_404>

LBB13_388:
    4407:	r9 = 4294967155 ll
    4409:	goto -4225 <LBB13_37>

LBB13_404:
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    4410:	r1 = *(u64 *)(r10 - 216)
    4411:	r7 = *(u32 *)(r1 + 0)
    4412:	r1 = 0
; struct metrics_value *entry, newEntry = {};
    4413:	*(u64 *)(r10 - 88) = r1
    4414:	*(u64 *)(r10 - 96) = r1
; struct metrics_key key = {};
    4415:	r1 = 512
    4416:	*(u64 *)(r10 - 40) = r1
    4417:	r2 = r10
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    4418:	r2 += -40
; if ((entry = map_lookup_elem(&cilium_metrics, &key))) {
    4419:	r1 = 0 ll
    4421:	call 1
    4422:	if r0 == 0 goto +7 <LBB13_406>
; entry->count += 1;
    4423:	r1 = *(u64 *)(r0 + 0)
    4424:	r1 += 1
    4425:	*(u64 *)(r0 + 0) = r1
; entry->bytes += (__u64)bytes;
    4426:	r1 = *(u64 *)(r0 + 8)
    4427:	r1 += r7
    4428:	*(u64 *)(r0 + 8) = r1
    4429:	goto +11 <LBB13_407>

LBB13_406:
; newEntry.bytes = (__u64)bytes;
    4430:	*(u64 *)(r10 - 88) = r7
; newEntry.count = 1;
    4431:	r1 = 1
    4432:	*(u64 *)(r10 - 96) = r1
    4433:	r2 = r10
; newEntry.bytes = (__u64)bytes;
    4434:	r2 += -40
    4435:	r3 = r10
    4436:	r3 += -96
; map_update_elem(&cilium_metrics, &key, &newEntry, 0);
    4437:	r1 = 0 ll
    4439:	r4 = 0
    4440:	call 2

LBB13_407:
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    4441:	r8 = *(u64 *)(r10 - 328)
    4442:	r8 <<= 32
    4443:	r8 >>= 32
; switch (obs_point) {
    4444:	if r8 == 0 goto +28 <LBB13_411>
    4445:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4446:	r7 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4447:	call 34
    4448:	r1 = 0
; struct trace_notify msg = {
    4449:	*(u32 *)(r10 - 72) = r1
    4450:	*(u32 *)(r10 - 92) = r0
    4451:	r1 = 269485060
    4452:	*(u32 *)(r10 - 96) = r1
    4453:	r1 = 2
    4454:	*(u64 *)(r10 - 80) = r1
    4455:	r1 = 1
    4456:	*(u32 *)(r10 - 68) = r1
    4457:	*(u32 *)(r10 - 88) = r7
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4458:	if r8 < r7 goto +1 <LBB13_410>
    4459:	r8 = r7

LBB13_410:
; struct trace_notify msg = {
    4460:	*(u32 *)(r10 - 84) = r8
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4461:	r8 <<= 32
    4462:	r1 = 4294967295 ll
    4464:	r8 |= r1
    4465:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4466:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4467:	r1 = *(u64 *)(r10 - 216)
    4468:	r2 = 0 ll
    4470:	r3 = r8
    4471:	r5 = 32
    4472:	call 25

LBB13_411:
; return redirect(ENCAP_IFINDEX, 0);
    4473:	r1 = 1
    4474:	r2 = 0
    4475:	call 23
    4476:	r9 = r0
    4477:	r1 = r9
    4478:	r1 <<= 32
    4479:	r1 >>= 32
; if (ret != DROP_NO_TUNNEL_ENDPOINT)
    4480:	r2 = 4294967136 ll
; }
    4482:	if r1 == r2 goto +1 <LBB13_413>
    4483:	goto -4299 <LBB13_37>

LBB13_413:
    4484:	r1 = r6
    4485:	r1 += 38
; return addr->p1 == 0 && addr->p2 == 0 && addr->p3 == 0xFFFF0000;
    4486:	r1 = *(u32 *)(r1 + 0)
    4487:	if r1 != 0 goto +11 <LBB13_417>
    4488:	r1 = *(u32 *)(r6 + 42)
    4489:	if r1 != 0 goto +9 <LBB13_417>
    4490:	r1 = *(u32 *)(r6 + 46)
    4491:	r2 = 4294901760 ll
; if (unlikely(ipv6_addr_is_mapped(daddr))) {
    4493:	if r1 != r2 goto +5 <LBB13_417>
; tail_call(skb, &CALLS_MAP, index);
    4494:	r1 = *(u64 *)(r10 - 216)
    4495:	r2 = 0 ll
    4497:	r3 = 8
    4498:	goto -628 <LBB13_374>

LBB13_417:
    4499:	r6 = *(u64 *)(r10 - 216)
; uint32_t hash = get_hash_recalc(skb);
    4500:	r1 = r6
    4501:	call 34
; struct debug_msg msg = {
    4502:	*(u32 *)(r10 - 92) = r0
    4503:	r1 = 269489154
    4504:	*(u32 *)(r10 - 96) = r1
    4505:	r1 = 0
    4506:	*(u64 *)(r10 - 88) = r1
    4507:	*(u32 *)(r10 - 80) = r1
    4508:	r4 = r10
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    4509:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4510:	r1 = r6
    4511:	r2 = 0 ll
    4513:	r3 = 4294967295 ll
    4515:	r5 = 20
    4516:	call 25
    4517:	r8 = 1
; hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
    4518:	r0 = *(u8 *)skb[21]
; if (hoplimit <= 1) {
    4519:	r1 = r0
    4520:	r1 &= 254
    4521:	r9 = 1
    4522:	if r1 == 0 goto +13 <LBB13_419>
; new_hl = hoplimit - 1;
    4523:	r0 += 255
    4524:	*(u8 *)(r10 - 96) = r0
    4525:	r3 = r10
    4526:	r3 += -96
; if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
    4527:	r1 = *(u64 *)(r10 - 216)
    4528:	r2 = 21
    4529:	r4 = 1
    4530:	r5 = 1
    4531:	call 9
    4532:	r9 = r0
    4533:	r9 <<= 32
; return DROP_WRITE_ERROR;
    4534:	r9 s>>= 63
    4535:	r9 &= -141

LBB13_419:
; if (IS_ERR(ret))
    4536:	if r9 == 2 goto +1 <LBB13_421>
    4537:	r8 = 0

LBB13_421:
    4538:	r1 = 2147483648 ll
    4540:	r2 = r9
    4541:	r2 &= r1
    4542:	r2 >>= 31
    4543:	r2 |= r8
    4544:	if r2 != 0 goto +13 <LBB13_425>
; if (ret > 0) {
    4545:	if r9 s< 1 goto +1 <LBB13_424>
    4546:	goto -684 <LBB13_372>

LBB13_424:
    4547:	r3 = r10
; static inline int eth_store_daddr(struct __sk_buff *skb, __u8 *mac, int off)
    4548:	r3 += -144
; return skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
    4549:	r1 = *(u64 *)(r10 - 216)
    4550:	r2 = 0
    4551:	r4 = 6
    4552:	r5 = 0
    4553:	call 9
    4554:	r9 = r0
    4555:	r9 <<= 32
; return DROP_WRITE_ERROR;
    4556:	r9 s>>= 63
    4557:	r9 &= -141

LBB13_425:
    4558:	r1 = *(u64 *)(r10 - 216)
; if (unlikely(ret != TC_ACT_OK))
    4559:	if r9 != 0 goto -4375 <LBB13_37>
    4560:	r3 = r10
; static inline int ipv6_store_flowlabel(struct __sk_buff *skb, int off, __be32 label)
    4561:	r3 += -96
; if (skb_load_bytes(skb, off, &old, 4) < 0)
    4562:	r2 = 14
    4563:	r4 = 4
    4564:	call 26
    4565:	r0 <<= 32
    4566:	r0 s>>= 32
    4567:	if r0 s> -1 goto +1 <LBB13_428>
    4568:	goto -162 <LBB13_388>

LBB13_428:
; old = bpf_htonl(0x60000000) | label | old;
    4569:	r1 = 1048575
    4570:	*(u32 *)(r10 - 96) = r1
    4571:	r3 = r10
    4572:	r3 += -96
    4573:	r6 = *(u64 *)(r10 - 216)
; if (skb_store_bytes(skb, off, &old, 4, BPF_F_RECOMPUTE_CSUM) < 0)
    4574:	r1 = r6
    4575:	r2 = 14
    4576:	r4 = 4
    4577:	r5 = 1
    4578:	call 9
    4579:	r9 = 4294967155 ll
    4581:	r0 <<= 32
    4582:	r0 s>>= 32
    4583:	r1 = *(u64 *)(r10 - 208)
; if (ipv6_store_flowlabel(skb, l3_off, SECLABEL_NB) < 0)
    4584:	if r0 s< 0 goto -4400 <LBB13_37>
; update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
    4585:	r7 = *(u32 *)(r6 + 0)
; send_trace_notify(skb, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
    4586:	r6 = *(u32 *)(r1 + 0)
    4587:	r1 = 0
; struct metrics_value *entry, newEntry = {};
    4588:	*(u64 *)(r10 - 88) = r1
    4589:	*(u64 *)(r10 - 96) = r1
; struct metrics_key key = {};
    4590:	r1 = 512
    4591:	*(u64 *)(r10 - 136) = r1
    4592:	r2 = r10
; send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
    4593:	r2 += -136
; if ((entry = map_lookup_elem(&cilium_metrics, &key))) {
    4594:	r1 = 0 ll
    4596:	call 1
    4597:	if r0 == 0 goto +7 <LBB13_443>
; entry->count += 1;
    4598:	r1 = *(u64 *)(r0 + 0)
    4599:	r1 += 1
    4600:	*(u64 *)(r0 + 0) = r1
; entry->bytes += (__u64)bytes;
    4601:	r1 = *(u64 *)(r0 + 8)
    4602:	r1 += r7
    4603:	*(u64 *)(r0 + 8) = r1
    4604:	goto +11 <LBB13_444>

LBB13_443:
; newEntry.bytes = (__u64)bytes;
    4605:	*(u64 *)(r10 - 88) = r7
; newEntry.count = 1;
    4606:	r1 = 1
    4607:	*(u64 *)(r10 - 96) = r1
    4608:	r2 = r10
; newEntry.bytes = (__u64)bytes;
    4609:	r2 += -136
    4610:	r3 = r10
    4611:	r3 += -96
; map_update_elem(&cilium_metrics, &key, &newEntry, 0);
    4612:	r1 = 0 ll
    4614:	r4 = 0
    4615:	call 2

LBB13_444:
    4616:	r1 = *(u64 *)(r10 - 328)
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    4617:	r1 <<= 32
    4618:	r1 >>= 32
    4619:	r8 = r1
; switch (obs_point) {
    4620:	if r1 == 0 goto +31 <LBB13_448>
    4621:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4622:	r7 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4623:	call 34
; struct trace_notify msg = {
    4624:	*(u32 *)(r10 - 92) = r0
    4625:	r1 = 269484804
    4626:	*(u32 *)(r10 - 96) = r1
    4627:	r1 = 2
    4628:	*(u32 *)(r10 - 80) = r1
    4629:	*(u32 *)(r10 - 76) = r6
    4630:	r1 = *(u64 *)(r10 - 312)
    4631:	*(u8 *)(r10 - 70) = r1
    4632:	r1 = 0
    4633:	*(u16 *)(r10 - 72) = r1
    4634:	*(u8 *)(r10 - 69) = r1
    4635:	*(u32 *)(r10 - 68) = r1
    4636:	*(u32 *)(r10 - 88) = r7
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4637:	if r8 < r7 goto +1 <LBB13_447>
    4638:	r8 = r7

LBB13_447:
    4639:	r3 = r8
; struct trace_notify msg = {
    4640:	*(u32 *)(r10 - 84) = r3
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4641:	r3 <<= 32
    4642:	r1 = 4294967295 ll
    4644:	r3 |= r1
    4645:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    4646:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4647:	r1 = *(u64 *)(r10 - 216)
    4648:	r2 = 0 ll
    4650:	r5 = 32
    4651:	call 25

LBB13_448:
    4652:	r1 = *(u64 *)(r10 - 216)
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4653:	r6 = *(u32 *)(r1 + 0)
; uint32_t hash = get_hash_recalc(skb);
    4654:	call 34
; struct debug_capture_msg msg = {
    4655:	*(u32 *)(r10 - 92) = r0
    4656:	r1 = 269485059
    4657:	*(u32 *)(r10 - 96) = r1
    4658:	*(u32 *)(r10 - 88) = r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4659:	if r6 < 128 goto +1 <LBB13_450>
    4660:	r6 = 128

LBB13_450:
; struct debug_capture_msg msg = {
    4661:	*(u32 *)(r10 - 84) = r6
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    4662:	r6 <<= 32
    4663:	r1 = 4294967295 ll
    4665:	r6 |= r1
    4666:	r9 = 0
; struct debug_capture_msg msg = {
    4667:	*(u64 *)(r10 - 80) = r9
    4668:	r4 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    4669:	r4 += -96
; skb_event_output(skb, &cilium_events,
    4670:	r1 = *(u64 *)(r10 - 216)
    4671:	r2 = 0 ll
    4673:	r3 = r6
    4674:	r5 = 24

LBB13_451:
    4675:	call 25
    4676:	goto -4492 <LBB13_37>

LBB13_464:
; struct ipv6_ct_tuple icmp_tuple = {
    4677:	r1 = 58
    4678:	*(u8 *)(r10 - 100) = r1
    4679:	*(u32 *)(r10 - 104) = r6
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    4680:	r1 = *(u16 *)(r10 - 60)
    4681:	r1 |= 16
; .flags = tuple->flags | TUPLE_F_RELATED,
    4682:	r2 = *(u8 *)(r7 + 37)
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    4683:	*(u16 *)(r10 - 60) = r1
; .flags = tuple->flags | TUPLE_F_RELATED,
    4684:	r2 |= 2
; struct ipv6_ct_tuple icmp_tuple = {
    4685:	*(u8 *)(r10 - 99) = r2
; dst->p1 = src->p1;
    4686:	r1 = *(u32 *)(r7 + 0)
    4687:	*(u32 *)(r10 - 136) = r1
; dst->p2 = src->p2;
    4688:	r1 = *(u32 *)(r7 + 4)
    4689:	*(u32 *)(r10 - 132) = r1
; dst->p3 = src->p3;
    4690:	r1 = *(u32 *)(r7 + 8)
    4691:	*(u32 *)(r10 - 128) = r1
; dst->p4 = src->p4;
    4692:	r1 = *(u32 *)(r7 + 12)
    4693:	*(u32 *)(r10 - 124) = r1
; dst->p1 = src->p1;
    4694:	r1 = *(u32 *)(r7 + 16)
    4695:	*(u32 *)(r10 - 120) = r1
; dst->p2 = src->p2;
    4696:	r1 = *(u32 *)(r7 + 20)
    4697:	*(u32 *)(r10 - 116) = r1
; dst->p3 = src->p3;
    4698:	r1 = *(u32 *)(r7 + 24)
    4699:	*(u32 *)(r10 - 112) = r1
; dst->p4 = src->p4;
    4700:	r1 = *(u32 *)(r7 + 28)
    4701:	*(u32 *)(r10 - 108) = r1
    4702:	r2 = r10
; struct ipv6_ct_tuple icmp_tuple = {
    4703:	r2 += -136
    4704:	r3 = r10
    4705:	r3 += -96
; if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
    4706:	r1 = r9
    4707:	r4 = 0
    4708:	call 2
    4709:	r0 <<= 32
    4710:	r0 s>>= 32
    4711:	r1 = *(u64 *)(r10 - 248)
; struct debug_msg msg = {
    4712:	r7 = 0
; if (IS_ERR(ret)) {
    4713:	if r0 s> -1 goto +4 <LBB13_466>

LBB13_465:
    4714:	r1 = *(u64 *)(r10 - 200)
    4715:	r2 = *(u64 *)(r10 - 296)
    4716:	*(u8 *)(r1 + 37) = r2
    4717:	goto -4034 <LBB13_95>

LBB13_466:
    4718:	r1 = *(u64 *)(r10 - 256)
    4719:	*(u64 *)(r10 - 256) = r1
    4720:	r9 = *(u64 *)(r10 - 248)
; key->slave = slave;
    4721:	*(u16 *)(r10 - 150) = r9
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);
    4722:	r6 = *(u16 *)(r10 - 152)
; uint32_t hash = get_hash_recalc(skb);
    4723:	r1 = r8
    4724:	call 34
; struct debug_msg msg = {
    4725:	*(u32 *)(r10 - 92) = r0
    4726:	r1 = 269490178
    4727:	*(u32 *)(r10 - 96) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);
    4728:	r1 = r9
    4729:	r1 &= 65535
; struct debug_msg msg = {
    4730:	*(u32 *)(r10 - 88) = r1
    4731:	*(u32 *)(r10 - 84) = r6
    4732:	*(u32 *)(r10 - 80) = r7
    4733:	r4 = r10
; key->slave = slave;
    4734:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4735:	r1 = r8
    4736:	r2 = 0 ll
    4738:	r3 = 4294967295 ll
    4740:	r5 = 20
    4741:	call 25
    4742:	r2 = r10
; key->slave = slave;
    4743:	r2 += -168
; svc = map_lookup_elem(&cilium_lb6_services, key);
    4744:	r1 = 0 ll
    4746:	call 1
; if (svc != NULL) {
    4747:	*(u64 *)(r10 - 248) = r9
    4748:	if r0 == 0 goto +135 <LBB13_479>
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE_SUCCESS, svc->target.p4, svc->port);
    4749:	r7 = *(u8 *)(r0 + 17)
    4750:	r7 <<= 8
    4751:	r1 = *(u8 *)(r0 + 16)
    4752:	r7 |= r1
    4753:	r1 = *(u8 *)(r0 + 14)
    4754:	*(u64 *)(r10 - 240) = r1
    4755:	r6 = *(u8 *)(r0 + 15)
    4756:	r1 = *(u8 *)(r0 + 12)
    4757:	*(u64 *)(r10 - 264) = r1
    4758:	r9 = *(u8 *)(r0 + 13)
; uint32_t hash = get_hash_recalc(skb);
    4759:	r1 = r8
    4760:	*(u64 *)(r10 - 280) = r0
    4761:	call 34
; struct debug_msg msg = {
    4762:	*(u32 *)(r10 - 92) = r0
    4763:	r1 = 269490434
    4764:	*(u32 *)(r10 - 96) = r1
    4765:	*(u32 *)(r10 - 84) = r7
    4766:	r1 = *(u64 *)(r10 - 224)
    4767:	r1 = 0
    4768:	*(u32 *)(r10 - 80) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE_SUCCESS, svc->target.p4, svc->port);
    4769:	r9 <<= 8
    4770:	r1 = *(u64 *)(r10 - 264)
    4771:	r9 |= r1
    4772:	r6 <<= 8
    4773:	r1 = *(u64 *)(r10 - 240)
    4774:	r6 |= r1
    4775:	r6 <<= 16
    4776:	r6 |= r9
; struct debug_msg msg = {
    4777:	*(u32 *)(r10 - 88) = r6
    4778:	r4 = r10
; struct ipv6_ct_tuple *tuple, struct lb6_service *svc,
    4779:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4780:	r1 = r8
    4781:	r2 = 0 ll
    4783:	r3 = 4294967295 ll
    4785:	r5 = 20
    4786:	call 25
    4787:	r3 = *(u64 *)(r10 - 280)
    4788:	r6 = *(u64 *)(r10 - 200)
    4789:	r2 = *(u64 *)(r10 - 296)

LBB13_468:
; tuple->flags = flags;
    4790:	*(u64 *)(r10 - 280) = r3
    4791:	*(u8 *)(r6 + 37) = r2
; dst->p1 = src->p1;
    4792:	r1 = *(u32 *)(r3 + 0)
    4793:	*(u32 *)(r6 + 0) = r1
; dst->p2 = src->p2;
    4794:	r1 = *(u32 *)(r3 + 4)
    4795:	*(u32 *)(r6 + 4) = r1
; dst->p3 = src->p3;
    4796:	r1 = *(u32 *)(r3 + 8)
    4797:	*(u32 *)(r6 + 8) = r1
; dst->p4 = src->p4;
    4798:	r1 = *(u32 *)(r3 + 12)
    4799:	*(u32 *)(r6 + 12) = r1
; state->rev_nat_index = svc->rev_nat_index;
    4800:	r9 = *(u8 *)(r3 + 20)
    4801:	r7 = *(u8 *)(r3 + 21)
; return lb6_xlate(skb, addr, tuple->nexthdr, l3_off, l4_off,
    4802:	r1 = *(u8 *)(r6 + 36)
; return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
    4803:	*(u64 *)(r10 - 240) = r1
    4804:	r1 = r8
    4805:	r2 = 38
    4806:	r3 = r6
    4807:	r4 = 16
    4808:	r5 = 0
    4809:	call 9
    4810:	r1 = r10
; struct ipv6_ct_tuple *tuple, struct lb6_service *svc,
    4811:	r1 += -168
; __be32 sum = csum_diff(key->address.addr, 16, new_dst->addr, 16, 0);
    4812:	r2 = 16
    4813:	r3 = r6
    4814:	r4 = 16
    4815:	r5 = 0
    4816:	call 28
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    4817:	r1 = *(u64 *)(r10 - 304)
    4818:	r1 &= 65535
    4819:	r6 = *(u64 *)(r10 - 232)
    4820:	r6 += r1
    4821:	r5 = *(u64 *)(r10 - 272)
    4822:	r5 |= 16
    4823:	r5 &= 65535
    4824:	r1 = r8
    4825:	r2 = r6
    4826:	r3 = 0
    4827:	r4 = r0
    4828:	call 11
; state->rev_nat_index = svc->rev_nat_index;
    4829:	r7 <<= 8
    4830:	r7 |= r9
    4831:	*(u64 *)(r10 - 264) = r7
    4832:	r9 = 4294967142 ll
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    4834:	r0 <<= 32
    4835:	r0 s>>= 32
    4836:	if r0 s< 0 goto -4151 <LBB13_96>
    4837:	r2 = *(u64 *)(r10 - 280)
; if (svc->port && key->dport != svc->port &&
    4838:	r1 = *(u8 *)(r2 + 16)
    4839:	r4 = *(u8 *)(r2 + 17)
    4840:	r4 <<= 8
    4841:	r4 |= r1
    4842:	if r4 == 0 goto +39 <LBB13_478>
    4843:	r3 = *(u16 *)(r10 - 152)
    4844:	if r3 == r4 goto +37 <LBB13_478>
; (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
    4845:	r1 = *(u64 *)(r10 - 240)
    4846:	if r1 == 17 goto +2 <LBB13_473>
    4847:	r1 = *(u64 *)(r10 - 240)
    4848:	if r1 != 6 goto +33 <LBB13_478>

LBB13_473:
    4849:	*(u16 *)(r10 - 96) = r4
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    4850:	r5 = *(u64 *)(r10 - 272)
    4851:	r5 |= 2
    4852:	r5 &= 65535
    4853:	r1 = r8
    4854:	r2 = r6
    4855:	call 11
    4856:	r9 = 4294967142 ll
    4858:	r0 <<= 32
    4859:	r0 s>>= 32
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    4860:	if r0 s< 0 goto +12 <LBB13_475>
; if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
    4861:	r2 = *(u64 *)(r10 - 224)
    4862:	r2 += 16
    4863:	r3 = r10
    4864:	r3 += -96
    4865:	r1 = r8
    4866:	r4 = 2
    4867:	r5 = 0
    4868:	call 9
    4869:	r9 = r0
    4870:	r9 <<= 32
; return DROP_WRITE_ERROR;
    4871:	r9 s>>= 63
    4872:	r9 &= -141

LBB13_475:
; if (IS_ERR(ret))
    4873:	r1 = r9
    4874:	r1 <<= 32
    4875:	r1 >>= 32
    4876:	r2 = 1
    4877:	if r1 == 2 goto +1 <LBB13_477>
    4878:	r2 = 0

LBB13_477:
    4879:	r1 >>= 31
    4880:	r1 |= r2
    4881:	if r1 != 0 goto -4196 <LBB13_96>

LBB13_478:
    4882:	r9 = 0
    4883:	goto -4198 <LBB13_96>

LBB13_479:
; if (key->dport) {
    4884:	r6 = *(u16 *)(r10 - 152)
    4885:	if r6 == 0 goto +31 <LBB13_483>
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4886:	r7 = *(u32 *)(r10 - 156)
; uint32_t hash = get_hash_recalc(skb);
    4887:	r1 = r8
    4888:	call 34
; struct debug_msg msg = {
    4889:	*(u32 *)(r10 - 92) = r0
    4890:	r1 = 269489666
    4891:	*(u32 *)(r10 - 96) = r1
    4892:	*(u32 *)(r10 - 88) = r7
    4893:	*(u32 *)(r10 - 84) = r6
    4894:	r6 = 0
    4895:	*(u32 *)(r10 - 80) = r6
    4896:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4897:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4898:	r1 = r8
    4899:	r2 = 0 ll
    4901:	r3 = 4294967295 ll
    4903:	r5 = 20
    4904:	call 25
    4905:	r2 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4906:	r2 += -168
; svc = map_lookup_elem(&cilium_lb6_services, key);
    4907:	r1 = 0 ll
    4909:	call 1
; if (svc && svc->count != 0)
    4910:	if r0 == 0 goto +5 <LBB13_482>
    4911:	r1 = *(u8 *)(r0 + 18)
    4912:	r9 = *(u8 *)(r0 + 19)
    4913:	r9 <<= 8
    4914:	r9 |= r1
    4915:	if r9 != 0 goto +51 <LBB13_486>

LBB13_482:
; key->dport = 0;
    4916:	*(u16 *)(r10 - 152) = r6

LBB13_483:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4917:	r6 = *(u32 *)(r10 - 156)
; uint32_t hash = get_hash_recalc(skb);
    4918:	r1 = r8
    4919:	call 34
; struct debug_msg msg = {
    4920:	*(u32 *)(r10 - 92) = r0
    4921:	r1 = 269489666
    4922:	*(u32 *)(r10 - 96) = r1
    4923:	*(u32 *)(r10 - 88) = r6
    4924:	r6 = 0
    4925:	*(u32 *)(r10 - 84) = r6
    4926:	*(u32 *)(r10 - 80) = r6
    4927:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4928:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4929:	r1 = r8
    4930:	r2 = 0 ll
    4932:	r3 = 4294967295 ll
    4934:	r5 = 20
    4935:	call 25
    4936:	r2 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
    4937:	r2 += -168
; svc = map_lookup_elem(&cilium_lb6_services, key);
    4938:	r1 = 0 ll
    4940:	call 1
; if (svc && svc->count != 0)
    4941:	if r0 == 0 goto +5 <LBB13_485>
    4942:	r1 = *(u8 *)(r0 + 18)
    4943:	r9 = *(u8 *)(r0 + 19)
    4944:	r9 <<= 8
    4945:	r9 |= r1
    4946:	if r9 != 0 goto +20 <LBB13_486>

LBB13_485:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
    4947:	r7 = *(u32 *)(r10 - 160)
    4948:	r9 = *(u32 *)(r10 - 164)
; uint32_t hash = get_hash_recalc(skb);
    4949:	r1 = r8
    4950:	call 34
; struct debug_msg msg = {
    4951:	*(u32 *)(r10 - 92) = r0
    4952:	r1 = 269489922
    4953:	*(u32 *)(r10 - 96) = r1
    4954:	*(u32 *)(r10 - 88) = r9
    4955:	*(u32 *)(r10 - 84) = r7
    4956:	*(u32 *)(r10 - 80) = r6
    4957:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
    4958:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    4959:	r1 = r8
    4960:	r2 = 0 ll
    4962:	r3 = 4294967295 ll
    4964:	r5 = 20
    4965:	call 25
    4966:	goto -253 <LBB13_465>

LBB13_486:
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
    4967:	r1 = *(u8 *)(r0 + 22)
    4968:	*(u64 *)(r10 - 248) = r1
    4969:	*(u64 *)(r10 - 280) = r0
    4970:	r7 = *(u8 *)(r0 + 23)
    4971:	r6 = r10
; struct ipv6_ct_tuple *tuple, struct lb6_service *svc,
    4972:	r6 += -96
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
    4973:	r1 = r8
    4974:	r2 = 0
    4975:	r3 = r6
    4976:	r4 = 4
    4977:	call 26
; skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
    4978:	r1 = r8
    4979:	r2 = 0
    4980:	r3 = r6
    4981:	r4 = 4
    4982:	r5 = 2
    4983:	call 9
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
    4984:	r7 <<= 8
    4985:	r1 = *(u64 *)(r10 - 248)
    4986:	r7 |= r1
; return get_hash_recalc(skb);
    4987:	r1 = r8
    4988:	call 34
    4989:	r6 = r0
; if (weight) {
    4990:	if r7 == 0 goto +29 <LBB13_491>
    4991:	r2 = r10
; struct lb6_key *key,
    4992:	r2 += -168
; seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
    4993:	r1 = 0 ll
    4995:	call 1
; if (seq && seq->count != 0)
    4996:	if r0 == 0 goto +23 <LBB13_491>
    4997:	r1 = *(u16 *)(r0 + 0)
    4998:	if r1 == 0 goto +21 <LBB13_491>
; slave = lb_next_rr(skb, seq, hash);
    4999:	r7 = r6
    5000:	r7 &= 65535
; __u8 offset = hash % seq->count;
    5001:	r2 = r7
    5002:	r2 /= r1
    5003:	r2 *= r1
    5004:	r1 = r7
    5005:	r1 -= r2
; if (offset < LB_RR_MAX_SEQ) {
    5006:	r1 &= 255
    5007:	if r1 > 30 goto +12 <LBB13_491>
; slave = seq->idx[offset] + 1;
    5008:	r1 <<= 1
    5009:	r0 += r1
    5010:	r6 = *(u16 *)(r0 + 2)
; uint32_t hash = get_hash_recalc(skb);
    5011:	r1 = r8
    5012:	call 34
; struct debug_msg msg = {
    5013:	*(u32 *)(r10 - 92) = r0
    5014:	r1 = 269493506
    5015:	*(u32 *)(r10 - 96) = r1
    5016:	*(u32 *)(r10 - 88) = r7
    5017:	r1 = 0
    5018:	*(u32 *)(r10 - 80) = r1
    5019:	goto +14 <LBB13_492>

LBB13_491:
; uint32_t hash = get_hash_recalc(skb);
    5020:	r1 = r8
    5021:	call 34
; struct debug_msg msg = {
    5022:	*(u32 *)(r10 - 92) = r0
    5023:	r1 = 269489410
    5024:	*(u32 *)(r10 - 96) = r1
    5025:	r1 = 0
    5026:	*(u32 *)(r10 - 80) = r1
    5027:	*(u32 *)(r10 - 88) = r6
; slave = (hash % count) + 1;
    5028:	r6 <<= 32
    5029:	r6 >>= 32
    5030:	r1 = r6
    5031:	r1 /= r9
    5032:	r1 *= r9
    5033:	r6 -= r1

LBB13_492:
    5034:	r6 += 1
    5035:	*(u64 *)(r10 - 248) = r6
; struct debug_msg msg = {
    5036:	*(u32 *)(r10 - 84) = r6
    5037:	r4 = r10
    5038:	r4 += -96
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    5039:	r1 = r8
    5040:	r2 = 0 ll
    5042:	r3 = 4294967295 ll
    5044:	r5 = 20
    5045:	call 25
; entry = map_lookup_elem(map, tuple);
    5046:	r1 = *(u64 *)(r10 - 240)
    5047:	r6 = *(u64 *)(r10 - 200)
    5048:	r2 = r6
    5049:	call 1
    5050:	r1 = *(u64 *)(r10 - 224)
    5051:	r2 = *(u64 *)(r10 - 296)
    5052:	r3 = *(u64 *)(r10 - 280)
; if (!entry)
    5053:	if r0 == 0 goto -264 <LBB13_468>
; entry->slave = state->slave;
    5054:	r1 = *(u64 *)(r10 - 248)
    5055:	*(u16 *)(r0 + 40) = r1
    5056:	goto -267 <LBB13_468>
Disassembly of section 2/1:
__send_drop_notify:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r7 = *(u32 *)(r6 + 0)
       2:	call 34
       3:	r1 = *(u32 *)(r6 + 52)
       4:	r2 = 4112
; struct lb6_key key = {};
       5:	*(u16 *)(r10 - 30) = r2
       6:	r2 = 1
       7:	*(u8 *)(r10 - 32) = r2
       8:	*(u32 *)(r10 - 28) = r0
       9:	r2 = r1
; tmp = a->p1 - b->p1;
      10:	r2 >>= 16
; if (!tmp)
      11:	*(u32 *)(r10 - 16) = r2
      12:	r1 &= 65535
      13:	*(u32 *)(r10 - 12) = r1
; tmp = a->p2 - b->p2;
      14:	*(u32 *)(r10 - 24) = r7
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	if r7 < 128 goto +1 <LBB0_2>
      16:	r7 = 128

LBB0_2:
      17:	*(u32 *)(r10 - 20) = r7
; tmp = a->p1 - b->p1;
      18:	r1 = *(u32 *)(r6 + 60)
; if (!tmp)
      19:	*(u32 *)(r10 - 8) = r1
      20:	r1 = *(u32 *)(r6 + 64)
      21:	*(u32 *)(r10 - 4) = r1
; tmp = a->p2 - b->p2;
      22:	r7 <<= 32
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r1 = 4294967295 ll
      25:	r7 |= r1
; tmp = a->p1 - b->p1;
      26:	r1 = *(u32 *)(r6 + 56)
; if (!tmp) {
      27:	r2 = r1
; tmp = a->p2 - b->p2;
      28:	r2 <<= 32
; if (!tmp) {
      29:	r2 s>>= 63
; tmp = a->p3 - b->p3;
      30:	r1 += r2
; if (!tmp)
      31:	r1 ^= r2
; tmp = a->p4 - b->p4;
      32:	*(u8 *)(r10 - 31) = r1
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r4 = r10
      34:	r4 += -32
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r1 = r6
      36:	r2 = 0 ll
; dst->p1 = src->p1;
      38:	r3 = r7
; dst->p2 = src->p2;
      39:	r5 = 32
      40:	call 25
; dst->p3 = src->p3;
      41:	r0 = *(u32 *)(r6 + 48)
      42:	exit
Disassembly of section 2/3:
tail_icmp6_send_echo_reply:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = *(u32 *)(r6 + 52)
       2:	*(u64 *)(r10 - 112) = r1
       3:	r7 = *(u32 *)(r6 + 48)
       4:	r8 = 0
; struct lb6_key key = {};
       5:	*(u64 *)(r10 - 96) = r8
       6:	r1 = r6
       7:	call 34
       8:	*(u32 *)(r10 - 20) = r0
       9:	r1 = 269487106
; tmp = a->p1 - b->p1;
      10:	*(u32 *)(r10 - 24) = r1
; if (!tmp)
      11:	*(u32 *)(r10 - 12) = r8
      12:	*(u32 *)(r10 - 8) = r8
      13:	*(u32 *)(r10 - 16) = r7
; tmp = a->p2 - b->p2;
      14:	r4 = r10
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r4 += -24
      16:	r1 = r6
      17:	r2 = 0 ll
; if (!tmp)
      19:	r3 = 4294967295 ll
      21:	r5 = 20
; tmp = a->p2 - b->p2;
      22:	call 25
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r8 = r7
      24:	r8 += 40
      25:	r3 = r10
; tmp = a->p1 - b->p1;
      26:	r3 += -104
; if (!tmp) {
      27:	r1 = r6
; tmp = a->p2 - b->p2;
      28:	r2 = r8
; if (!tmp) {
      29:	r4 = 8
; tmp = a->p3 - b->p3;
      30:	call 26
; if (!tmp)
      31:	r9 = 4294967162 ll
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r0 <<= 32
      34:	r0 s>>= 32
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	if r0 s< 0 goto +200 <LBB1_15>
      36:	r1 = 129
; dst->p1 = src->p1;
      37:	*(u16 *)(r10 - 96) = r1
      38:	r1 = *(u16 *)(r10 - 102)
; dst->p2 = src->p2;
      39:	*(u16 *)(r10 - 94) = r1
      40:	r1 = *(u16 *)(r10 - 100)
; dst->p3 = src->p3;
      41:	*(u16 *)(r10 - 92) = r1
      42:	r1 = *(u16 *)(r10 - 98)
; dst->p4 = src->p4;
      43:	*(u16 *)(r10 - 90) = r1
      44:	r3 = r10
; dst->p1 = src->p1;
      45:	r3 += -96
      46:	r1 = r6
; dst->p2 = src->p2;
      47:	r2 = r8
      48:	r4 = 8
; dst->p3 = src->p3;
      49:	r5 = 0
      50:	call 9
; dst->p4 = src->p4;
      51:	r9 = 4294967155 ll
      53:	r0 <<= 32
      54:	r0 s>>= 32
; __u8 nh = *nexthdr;
      55:	if r0 s< 0 goto +180 <LBB1_15>
; switch (nh) {
      56:	r8 = r7
      57:	r8 += 42
      58:	r1 = r10
      59:	r1 += -104
      60:	r3 = r10
      61:	r3 += -96
      62:	r2 = 8
      63:	r4 = 8
      64:	r5 = 0
      65:	call 28
      66:	r1 = r6
      67:	r2 = r8
      68:	r3 = 0
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r4 = r0
      70:	r5 = 16
      71:	call 11
      72:	r9 = 4294967142 ll
      74:	r0 <<= 32
      75:	r0 s>>= 32
      76:	if r0 s< 0 goto +159 <LBB1_15>
      77:	*(u64 *)(r10 - 120) = r8
      78:	r1 = 244920237338078 ll
; nh = opthdr.nexthdr;
      80:	*(u64 *)(r10 - 40) = r1
; if (nh == NEXTHDR_AUTH)
      81:	r8 = r7
      82:	r8 += 8
      83:	r3 = r10
      84:	r3 += -56
      85:	r1 = r6
      86:	r2 = r8
; switch (nh) {
      87:	r4 = 16
      88:	call 26
      89:	r0 <<= 32
      90:	r0 s>>= 32
      91:	r9 = 4294967162 ll
      93:	if r0 s< 0 goto +142 <LBB1_15>
      94:	r7 += 24
      95:	r3 = r10
      96:	r3 += -72
      97:	r1 = r6
      98:	r2 = r7
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r4 = 16
     100:	call 26
     101:	r0 <<= 32
     102:	r0 s>>= 32
     103:	r9 = 4294967162 ll
     105:	if r0 s< 0 goto +130 <LBB1_15>
     106:	r1 = 61374
     107:	*(u64 *)(r10 - 88) = r1
     108:	r1 = 1099528404992 ll
; nh = opthdr.nexthdr;
     110:	*(u64 *)(r10 - 80) = r1
; if (nh == NEXTHDR_AUTH)
     111:	r3 = r10
     112:	r3 += -88
     113:	r1 = r6
     114:	r2 = r8
     115:	r4 = 16
     116:	r5 = 0
     117:	call 9
; switch (nh) {
     118:	r0 <<= 32
     119:	r0 s>>= 32
     120:	r9 = 4294967155 ll
     122:	if r0 s< 0 goto +113 <LBB1_15>
     123:	r3 = r10
     124:	r3 += -56
     125:	r1 = r6
     126:	r2 = r7
     127:	r4 = 16
     128:	r5 = 0
     129:	call 9
     130:	r0 <<= 32
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r0 s>>= 32
     132:	r9 = 4294967155 ll
     134:	if r0 s< 0 goto +101 <LBB1_15>
     135:	r1 = r10
     136:	r1 += -56
     137:	r3 = r10
     138:	r3 += -88
     139:	r2 = 16
     140:	r4 = 16
     141:	r5 = 0
; nh = opthdr.nexthdr;
     142:	call 28
; if (nh == NEXTHDR_AUTH)
     143:	r1 = r6
     144:	r2 = *(u64 *)(r10 - 120)
     145:	r3 = 0
     146:	r4 = r0
     147:	r5 = 16
     148:	call 11
     149:	r9 = 4294967142 ll
     151:	r0 <<= 32
     152:	r0 s>>= 32
     153:	if r0 s< 0 goto +82 <LBB1_15>
     154:	r1 = r10
     155:	r1 += -72
     156:	r3 = r10
     157:	r3 += -56
     158:	r2 = 16
     159:	r4 = 16
     160:	r5 = 0
     161:	call 28
     162:	r1 = r6
; *nexthdr = nh;
     163:	r2 = *(u64 *)(r10 - 120)
; dst->p1 = src->p1;
     164:	r3 = 0
     165:	r4 = r0
; dst->p2 = src->p2;
     166:	r5 = 16
     167:	call 11
; dst->p3 = src->p3;
     168:	r0 <<= 32
     169:	r0 s>>= 32
; dst->p4 = src->p4;
     170:	if r0 s< 0 goto +65 <LBB1_15>
     171:	r3 = r10
     172:	r3 += -32
     173:	r1 = r6
     174:	r2 = 6
; switch (nexthdr) {
     175:	r4 = 6
     176:	call 26
     177:	r0 <<= 32
     178:	r0 s>>= 32
     179:	r9 = 4294967162 ll
     181:	if r0 s< 0 goto +54 <LBB1_15>
     182:	r3 = r10
     183:	r3 += -32
     184:	r1 = r6
; }
     185:	r2 = 0
     186:	r4 = 6
; switch (nexthdr) {
     187:	r5 = 0
     188:	call 9
     189:	r0 <<= 32
     190:	r0 s>>= 32
     191:	r9 = 4294967155 ll
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	if r0 s< 0 goto +42 <LBB1_15>
     194:	r3 = r10
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r3 += -40
     196:	r1 = r6
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r2 = 6
     198:	r4 = 6
     199:	r5 = 0
     200:	call 9
     201:	r0 <<= 32
     202:	r0 s>>= 32
     203:	r9 = 4294967155 ll
; if (IS_ERR(ret))
     205:	if r0 s< 0 goto +30 <LBB1_15>
     206:	r7 = *(u32 *)(r6 + 0)
     207:	r8 = *(u32 *)(r6 + 40)
     208:	r1 = r6
     209:	call 34
     210:	*(u32 *)(r10 - 20) = r0
     211:	r1 = 269485059
     212:	*(u32 *)(r10 - 24) = r1
     213:	*(u32 *)(r10 - 8) = r8
; if (IS_ERR(ret)) {
     214:	*(u32 *)(r10 - 16) = r7
     215:	if r7 < 128 goto +1 <LBB1_14>
     216:	r7 = 128

LBB1_14:
     217:	*(u32 *)(r10 - 12) = r7
     218:	r7 <<= 32
     219:	r1 = 4294967295 ll
     221:	r7 |= r1
     222:	r1 = 0
     223:	*(u32 *)(r10 - 4) = r1
     224:	r4 = r10
     225:	r4 += -24
     226:	r1 = r6
     227:	r2 = 0 ll
; if (ret == DROP_UNKNOWN_L4)
     229:	r3 = r7
     230:	r5 = 24
     231:	call 25
     232:	r1 = *(u32 *)(r6 + 40)
     233:	r2 = 0
     234:	call 23
     235:	r9 = r0

LBB1_15:
     236:	r1 = r9
     237:	r1 <<= 32
     238:	r1 >>= 32
     239:	r2 = 1
     240:	if r1 == 2 goto +1 <LBB1_17>
; if (key->dport) {
     241:	r2 = 0

LBB1_17:
     242:	r1 >>= 31
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r1 |= r2
; uint32_t hash = get_hash_recalc(skb);
     244:	if r1 == 0 goto +46 <LBB1_22>
     245:	r1 = 2
; struct debug_msg msg = {
     246:	*(u32 *)(r6 + 48) = r1
     247:	r1 = 0
     248:	*(u32 *)(r6 + 52) = r1
     249:	*(u32 *)(r6 + 56) = r9
     250:	*(u32 *)(r6 + 60) = r1
     251:	*(u32 *)(r6 + 64) = r1
     252:	r7 = *(u32 *)(r6 + 0)
     253:	*(u64 *)(r10 - 16) = r1
     254:	*(u64 *)(r10 - 24) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	*(u64 *)(r10 - 56) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r1 = *(u64 *)(r10 - 112)
     257:	r1 &= 3
     258:	*(u8 *)(r10 - 55) = r1
     259:	r9 = -r9
     260:	*(u8 *)(r10 - 56) = r9
     261:	r2 = r10
     262:	r2 += -56
     263:	r1 = 0 ll
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	call 1
     266:	if r0 == 0 goto +7 <LBB1_20>
     267:	r1 = *(u64 *)(r0 + 0)
; if (svc && svc->count != 0)
     268:	r1 += 1
     269:	*(u64 *)(r0 + 0) = r1
     270:	r1 = *(u64 *)(r0 + 8)
     271:	r1 += r7
     272:	*(u64 *)(r0 + 8) = r1
     273:	goto +11 <LBB1_21>

LBB1_20:
; key->dport = 0;
     274:	*(u64 *)(r10 - 16) = r7
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r1 = 1
; uint32_t hash = get_hash_recalc(skb);
     276:	*(u64 *)(r10 - 24) = r1
     277:	r2 = r10
; struct debug_msg msg = {
     278:	r2 += -56
     279:	r3 = r10
     280:	r3 += -24
     281:	r1 = 0 ll
     283:	r4 = 0
     284:	call 2

LBB1_21:
     285:	r1 = r6
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r2 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     288:	r3 = 1
     289:	call 12
     290:	r9 = 2

LBB1_22:
     291:	r0 = r9
     292:	exit
Disassembly of section 2/5:
tail_icmp6_send_time_exceeded:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = *(u32 *)(r6 + 52)
       2:	*(u64 *)(r10 - 184) = r1
       3:	r7 = *(u32 *)(r6 + 48)
       4:	r8 = 0
; struct lb6_key key = {};
       5:	*(u8 *)(r10 - 89) = r8
       6:	*(u8 *)(r10 - 90) = r8
       7:	*(u8 *)(r10 - 91) = r8
       8:	*(u8 *)(r10 - 92) = r8
       9:	*(u8 *)(r10 - 93) = r8
; tmp = a->p1 - b->p1;
      10:	*(u8 *)(r10 - 94) = r8
; if (!tmp)
      11:	*(u8 *)(r10 - 95) = r8
      12:	*(u8 *)(r10 - 96) = r8
      13:	*(u8 *)(r10 - 97) = r8
; tmp = a->p2 - b->p2;
      14:	*(u8 *)(r10 - 98) = r8
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	*(u8 *)(r10 - 99) = r8
      16:	*(u8 *)(r10 - 100) = r8
      17:	*(u8 *)(r10 - 101) = r8
; tmp = a->p1 - b->p1;
      18:	*(u8 *)(r10 - 102) = r8
; if (!tmp)
      19:	*(u8 *)(r10 - 103) = r8
      20:	*(u8 *)(r10 - 104) = r8
      21:	*(u8 *)(r10 - 105) = r8
; tmp = a->p2 - b->p2;
      22:	*(u8 *)(r10 - 106) = r8
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	*(u8 *)(r10 - 107) = r8
      24:	*(u8 *)(r10 - 108) = r8
      25:	*(u8 *)(r10 - 109) = r8
; tmp = a->p1 - b->p1;
      26:	*(u8 *)(r10 - 110) = r8
; if (!tmp) {
      27:	*(u8 *)(r10 - 111) = r8
; tmp = a->p2 - b->p2;
      28:	*(u8 *)(r10 - 112) = r8
; if (!tmp) {
      29:	*(u8 *)(r10 - 113) = r8
; tmp = a->p3 - b->p3;
      30:	*(u8 *)(r10 - 114) = r8
; if (!tmp)
      31:	*(u8 *)(r10 - 115) = r8
; tmp = a->p4 - b->p4;
      32:	*(u8 *)(r10 - 116) = r8
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	*(u8 *)(r10 - 117) = r8
      34:	*(u8 *)(r10 - 118) = r8
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	*(u8 *)(r10 - 119) = r8
      36:	*(u8 *)(r10 - 120) = r8
; dst->p1 = src->p1;
      37:	*(u8 *)(r10 - 121) = r8
      38:	*(u8 *)(r10 - 122) = r8
; dst->p2 = src->p2;
      39:	*(u8 *)(r10 - 123) = r8
      40:	*(u8 *)(r10 - 124) = r8
; dst->p3 = src->p3;
      41:	*(u8 *)(r10 - 125) = r8
      42:	*(u8 *)(r10 - 126) = r8
; dst->p4 = src->p4;
      43:	*(u8 *)(r10 - 127) = r8
      44:	*(u8 *)(r10 - 128) = r8
; dst->p1 = src->p1;
      45:	*(u8 *)(r10 - 129) = r8
      46:	*(u8 *)(r10 - 130) = r8
; dst->p2 = src->p2;
      47:	*(u8 *)(r10 - 131) = r8
      48:	*(u8 *)(r10 - 132) = r8
; dst->p3 = src->p3;
      49:	*(u8 *)(r10 - 133) = r8
      50:	*(u8 *)(r10 - 134) = r8
; dst->p4 = src->p4;
      51:	*(u8 *)(r10 - 135) = r8
      52:	*(u8 *)(r10 - 136) = r8
      53:	*(u8 *)(r10 - 137) = r8
      54:	*(u8 *)(r10 - 138) = r8
; __u8 nh = *nexthdr;
      55:	*(u8 *)(r10 - 139) = r8
; switch (nh) {
      56:	*(u8 *)(r10 - 140) = r8
      57:	*(u8 *)(r10 - 141) = r8
      58:	*(u8 *)(r10 - 142) = r8
      59:	*(u8 *)(r10 - 143) = r8
      60:	*(u8 *)(r10 - 144) = r8
      61:	*(u8 *)(r10 - 145) = r8
      62:	*(u8 *)(r10 - 146) = r8
      63:	*(u8 *)(r10 - 147) = r8
      64:	*(u8 *)(r10 - 148) = r8
      65:	*(u8 *)(r10 - 149) = r8
      66:	*(u8 *)(r10 - 150) = r8
      67:	*(u8 *)(r10 - 151) = r8
      68:	*(u8 *)(r10 - 152) = r8
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	*(u8 *)(r10 - 153) = r8
      70:	*(u8 *)(r10 - 154) = r8
      71:	*(u8 *)(r10 - 155) = r8
      72:	*(u8 *)(r10 - 156) = r8
      73:	*(u8 *)(r10 - 157) = r8
      74:	*(u8 *)(r10 - 158) = r8
      75:	*(u8 *)(r10 - 159) = r8
      76:	*(u8 *)(r10 - 160) = r8
      77:	*(u16 *)(r10 - 170) = r8
      78:	r1 = 58
      79:	*(u8 *)(r10 - 171) = r1
; nh = opthdr.nexthdr;
      80:	r1 = 3
; if (nh == NEXTHDR_AUTH)
      81:	*(u32 *)(r10 - 168) = r1
      82:	*(u32 *)(r10 - 164) = r8
      83:	r1 = r6
      84:	call 34
      85:	*(u32 *)(r10 - 20) = r0
      86:	r1 = 269487618
; switch (nh) {
      87:	*(u32 *)(r10 - 24) = r1
      88:	*(u64 *)(r10 - 16) = r8
      89:	*(u32 *)(r10 - 8) = r8
      90:	r4 = r10
      91:	r4 += -24
      92:	r1 = r6
      93:	r2 = 0 ll
      95:	r3 = 4294967295 ll
      97:	r5 = 20
      98:	call 25
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r3 = r10
     100:	r3 += -160
     101:	r1 = r6
     102:	r2 = r7
     103:	r4 = 40
     104:	call 26
     105:	r9 = 4294967162 ll
     107:	r0 <<= 32
     108:	r0 s>>= 32
     109:	if r0 s< 0 goto +376 <LBB2_26>
; nh = opthdr.nexthdr;
     110:	r2 = r7
; if (nh == NEXTHDR_AUTH)
     111:	r2 += 6
     112:	r3 = r10
     113:	r3 += -171
     114:	r1 = r6
     115:	r4 = 1
     116:	r5 = 0
     117:	call 9
; switch (nh) {
     118:	r0 <<= 32
     119:	r0 s>>= 32
     120:	r9 = 4294967155 ll
     122:	if r0 s< 0 goto +363 <LBB2_26>
     123:	r3 = r10
     124:	r3 += -120
     125:	r1 = *(u8 *)(r10 - 154)
     126:	if r1 == 6 goto +96 <LBB2_9>
     127:	if r1 == 58 goto +3 <LBB2_5>
     128:	r9 = 4294967154 ll
     130:	if r1 != 17 goto +355 <LBB2_26>

LBB2_5:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r8 = r7
     132:	r8 += 40
     133:	r1 = r6
     134:	r2 = r8
     135:	r4 = 8
     136:	call 26
     137:	r0 <<= 32
     138:	r0 s>>= 32
     139:	r9 = 4294967162 ll
     141:	if r0 s< 0 goto +344 <LBB2_26>
; nh = opthdr.nexthdr;
     142:	r3 = r10
; if (nh == NEXTHDR_AUTH)
     143:	r3 += -168
     144:	r1 = 0
     145:	r2 = 0
     146:	r4 = 56
     147:	r5 = 0
     148:	call 28
     149:	r1 = 939524096
; switch (nh) {
     150:	*(u32 *)(r10 - 24) = r1
     151:	r1 = 973078528
     152:	*(u32 *)(r10 - 56) = r1
     153:	r3 = r10
     154:	r3 += -152
     155:	r1 = 0
     156:	r2 = 0
     157:	r4 = 16
     158:	r5 = r0
     159:	call 28
     160:	r3 = r10
     161:	r3 += -136
     162:	r1 = 0
; *nexthdr = nh;
     163:	r2 = 0
; dst->p1 = src->p1;
     164:	r4 = 16
     165:	r5 = r0
; dst->p2 = src->p2;
     166:	call 28
     167:	r3 = r10
; dst->p3 = src->p3;
     168:	r3 += -24
     169:	r1 = 0
; dst->p4 = src->p4;
     170:	r2 = 0
     171:	r4 = 4
     172:	r5 = r0
     173:	call 28
     174:	r3 = r10
; switch (nexthdr) {
     175:	r3 += -56
     176:	r1 = 0
     177:	r2 = 0
     178:	r4 = 4
     179:	r5 = r0
     180:	call 28
     181:	*(u64 *)(r10 - 192) = r0
     182:	r1 = 14336
     183:	*(u16 *)(r10 - 170) = r1
     184:	r1 = *(u16 *)(r10 - 156)
; }
     185:	r1 = be16 r1
     186:	r2 = *(u32 *)(r6 + 0)
; switch (nexthdr) {
     187:	r2 += 56
     188:	r2 -= r1
     189:	r1 = r6
     190:	r3 = 0
     191:	call 38
     192:	r0 <<= 32
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r0 s>>= 32
     194:	r9 = 4294967155 ll
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     196:	if r0 s< 0 goto +289 <LBB2_26>
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r3 = r10
     198:	r3 += -168
     199:	r1 = r6
     200:	r2 = r8
     201:	r4 = 56
     202:	r5 = 0
     203:	call 9
; if (IS_ERR(ret))
     204:	r0 <<= 32
     205:	r0 s>>= 32
     206:	r9 = 4294967155 ll
     208:	if r0 s< 0 goto +277 <LBB2_26>
     209:	r2 = r7
     210:	r2 += 4
     211:	r3 = r10
     212:	r3 += -170
     213:	r1 = r6
; if (IS_ERR(ret)) {
     214:	r4 = 2
     215:	r5 = 0
     216:	call 9
     217:	r0 <<= 32
     218:	r0 s>>= 32
     219:	r9 = 4294967155 ll
     221:	if r0 s< 0 goto +264 <LBB2_26>
     222:	goto +91 <LBB2_13>

LBB2_9:
     223:	r8 = r7
     224:	r8 += 40
     225:	r1 = r6
     226:	r2 = r8
     227:	r4 = 20
; if (ret == DROP_UNKNOWN_L4)
     228:	call 26
     229:	r0 <<= 32
     230:	r0 s>>= 32
     231:	r9 = 4294967162 ll
     233:	if r0 s< 0 goto +252 <LBB2_26>
     234:	r3 = r10
     235:	r3 += -168
     236:	r1 = 0
     237:	r2 = 0
     238:	r4 = 68
     239:	r5 = 0
     240:	call 28
; if (key->dport) {
     241:	r1 = 1140850688
     242:	*(u32 *)(r10 - 24) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r1 = 973078528
; uint32_t hash = get_hash_recalc(skb);
     244:	*(u32 *)(r10 - 56) = r1
     245:	r3 = r10
; struct debug_msg msg = {
     246:	r3 += -152
     247:	r1 = 0
     248:	r2 = 0
     249:	r4 = 16
     250:	r5 = r0
     251:	call 28
     252:	r3 = r10
     253:	r3 += -136
     254:	r1 = 0
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	r2 = 0
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r4 = 16
     257:	r5 = r0
     258:	call 28
     259:	r3 = r10
     260:	r3 += -24
     261:	r1 = 0
     262:	r2 = 0
     263:	r4 = 4
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r5 = r0
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	call 28
     266:	r3 = r10
     267:	r3 += -56
; if (svc && svc->count != 0)
     268:	r1 = 0
     269:	r2 = 0
     270:	r4 = 4
     271:	r5 = r0
     272:	call 28
     273:	*(u64 *)(r10 - 192) = r0
; key->dport = 0;
     274:	r1 = 17408
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	*(u16 *)(r10 - 170) = r1
; uint32_t hash = get_hash_recalc(skb);
     276:	r1 = *(u16 *)(r10 - 156)
     277:	r1 = be16 r1
; struct debug_msg msg = {
     278:	r2 = *(u32 *)(r6 + 0)
     279:	r2 += 68
     280:	r2 -= r1
     281:	r1 = r6
     282:	r3 = 0
     283:	call 38
     284:	r0 <<= 32
     285:	r0 s>>= 32
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r9 = 4294967155 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     288:	if r0 s< 0 goto +197 <LBB2_26>
     289:	r3 = r10
     290:	r3 += -168
     291:	r1 = r6
     292:	r2 = r8
     293:	r4 = 68
     294:	r5 = 0
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	call 9
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r0 <<= 32
     297:	r0 s>>= 32
     298:	r9 = 4294967155 ll
; if (svc && svc->count != 0)
     300:	if r0 s< 0 goto +185 <LBB2_26>
     301:	r2 = r7
     302:	r2 += 4
     303:	r3 = r10
     304:	r3 += -170
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r1 = r6
     306:	r4 = 2
; uint32_t hash = get_hash_recalc(skb);
     307:	r5 = 0
     308:	call 9
; struct debug_msg msg = {
     309:	r0 <<= 32
     310:	r0 s>>= 32
     311:	r9 = 4294967155 ll
     313:	if r0 s< 0 goto +172 <LBB2_26>

LBB2_13:
     314:	r8 = r7
     315:	r8 += 42
     316:	r1 = r6
     317:	r2 = r8
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	r3 = 0
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r4 = *(u64 *)(r10 - 192)
     320:	r5 = 16
     321:	call 11
     322:	r9 = 4294967142 ll
     324:	r0 <<= 32
     325:	r0 s>>= 32
     326:	if r0 s< 0 goto +159 <LBB2_26>
     327:	*(u64 *)(r10 - 192) = r8
     328:	r1 = 244920237338078 ll
     330:	*(u64 *)(r10 - 40) = r1
     331:	r8 = r7
     332:	r8 += 8
; __u8 flags = tuple->flags;
     333:	r3 = r10
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	r3 += -56
; union tcp_flags tcp_flags = { 0 };
     335:	r1 = r6
     336:	r2 = r8
; tuple->flags = TUPLE_F_SERVICE;
     337:	r4 = 16
     338:	call 26
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r0 <<= 32
     340:	r0 s>>= 32
     341:	r9 = 4294967162 ll
     343:	if r0 s< 0 goto +142 <LBB2_26>
     344:	r7 += 24
; switch (tuple->nexthdr) {
     345:	r3 = r10
     346:	r3 += -72
     347:	r1 = r6
     348:	r2 = r7
     349:	r4 = 16
     350:	call 26
; __u8 type;
     351:	r0 <<= 32
     352:	r0 s>>= 32
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	r9 = 4294967162 ll
     355:	if r0 s< 0 goto +130 <LBB2_26>
     356:	r1 = 61374
     357:	*(u64 *)(r10 - 88) = r1
     358:	r1 = 1099528404992 ll
     360:	*(u64 *)(r10 - 80) = r1
     361:	r3 = r10
; tuple->dport = 0;
     362:	r3 += -88
     363:	r1 = r6
; tuple->sport = 0;
     364:	r2 = r8
     365:	r4 = 16
     366:	r5 = 0
; switch (type) {
     367:	call 9
     368:	r0 <<= 32
     369:	r0 s>>= 32
     370:	r9 = 4294967155 ll
     372:	if r0 s< 0 goto +113 <LBB2_26>
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r3 = r10
     374:	r3 += -56
     375:	r1 = r6
     376:	r2 = r7
     377:	r4 = 16
     378:	r5 = 0
     379:	call 9
     380:	r0 <<= 32
     381:	r0 s>>= 32
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	r9 = 4294967155 ll
     384:	if r0 s< 0 goto +101 <LBB2_26>
     385:	r1 = r10
     386:	r1 += -56
     387:	r3 = r10
     388:	r3 += -88
     389:	r2 = 16
     390:	r4 = 16
     391:	r5 = 0
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     392:	call 28
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	r1 = r6
     394:	r2 = *(u64 *)(r10 - 192)
     395:	r3 = 0
     396:	r4 = r0
     397:	r5 = 16
     398:	call 11
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	r9 = 4294967142 ll
     401:	r0 <<= 32
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r0 s>>= 32
     403:	if r0 s< 0 goto +82 <LBB2_26>
     404:	r1 = r10
     405:	r1 += -72
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	r3 = r10
     407:	r3 += -56
     408:	r2 = 16
     409:	r4 = 16
     410:	r5 = 0
     411:	call 28
     412:	r1 = r6
     413:	r2 = *(u64 *)(r10 - 192)
     414:	r3 = 0
     415:	r4 = r0
     416:	r5 = 16
     417:	call 11
     418:	r0 <<= 32
     419:	r0 s>>= 32
; tuple->flags |= TUPLE_F_RELATED;
     420:	if r0 s< 0 goto +65 <LBB2_26>
     421:	r3 = r10
     422:	r3 += -32
     423:	r1 = r6
; break;
     424:	r2 = 6
     425:	r4 = 6
; tuple->sport = type;
     426:	call 26
     427:	r0 <<= 32
     428:	r0 s>>= 32
     429:	r9 = 4294967162 ll
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	if r0 s< 0 goto +54 <LBB2_26>
     432:	r3 = r10
     433:	r3 += -32
     434:	r1 = r6
     435:	r2 = 0
     436:	r4 = 6
     437:	r5 = 0
     438:	call 9
     439:	r0 <<= 32
     440:	r0 s>>= 32
     441:	r9 = 4294967155 ll
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	if r0 s< 0 goto +42 <LBB2_26>
     444:	r3 = r10
     445:	r3 += -40
     446:	r1 = r6
     447:	r2 = 6
     448:	r4 = 6
     449:	r5 = 0
     450:	call 9
     451:	r0 <<= 32
     452:	r0 s>>= 32
     453:	r9 = 4294967155 ll
     455:	if r0 s< 0 goto +30 <LBB2_26>
     456:	r7 = *(u32 *)(r6 + 0)
     457:	r8 = *(u32 *)(r6 + 40)
     458:	r1 = r6
     459:	call 34
     460:	*(u32 *)(r10 - 20) = r0
     461:	r1 = 269485059
     462:	*(u32 *)(r10 - 24) = r1
     463:	*(u32 *)(r10 - 8) = r8
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	*(u32 *)(r10 - 16) = r7
     465:	if r7 < 128 goto +1 <LBB2_25>
     466:	r7 = 128

LBB2_25:
     467:	*(u32 *)(r10 - 12) = r7
     468:	r7 <<= 32
     469:	r1 = 4294967295 ll
; uint32_t hash = get_hash_recalc(skb);
     471:	r7 |= r1
     472:	r1 = 0
; struct debug_msg msg = {
     473:	*(u32 *)(r10 - 4) = r1
     474:	r4 = r10
     475:	r4 += -24
     476:	r1 = r6
     477:	r2 = 0 ll
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	r3 = r7
     480:	r5 = 24
     481:	call 25
     482:	r1 = *(u32 *)(r6 + 40)
     483:	r2 = 0
     484:	call 23
     485:	r9 = r0

LBB2_26:
     486:	r1 = r9
     487:	r1 <<= 32
; struct debug_msg msg = {
     488:	r1 >>= 32
     489:	r2 = 1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     490:	if r1 == 2 goto +1 <LBB2_28>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     491:	r2 = 0

LBB2_28:
     492:	r1 >>= 31
     493:	r1 |= r2
     494:	if r1 == 0 goto +46 <LBB2_33>
     495:	r1 = 2
     496:	*(u32 *)(r6 + 48) = r1
     497:	r1 = 0
     498:	*(u32 *)(r6 + 52) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     499:	*(u32 *)(r6 + 56) = r9
     500:	*(u32 *)(r6 + 60) = r1
; uint32_t hash = get_hash_recalc(skb);
     501:	*(u32 *)(r6 + 64) = r1
     502:	r7 = *(u32 *)(r6 + 0)
; struct debug_msg msg = {
     503:	*(u64 *)(r10 - 160) = r1
     504:	*(u64 *)(r10 - 168) = r1
     505:	*(u64 *)(r10 - 24) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     506:	r1 = *(u64 *)(r10 - 184)
     507:	r1 &= 3
; struct debug_msg msg = {
     508:	*(u8 *)(r10 - 23) = r1
     509:	r9 = -r9
     510:	*(u8 *)(r10 - 24) = r9
     511:	r2 = r10
     512:	r2 += -24
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     513:	r1 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     515:	call 1
     516:	if r0 == 0 goto +7 <LBB2_31>
     517:	r1 = *(u64 *)(r0 + 0)
     518:	r1 += 1
     519:	*(u64 *)(r0 + 0) = r1
     520:	r1 = *(u64 *)(r0 + 8)
     521:	r1 += r7
     522:	*(u64 *)(r0 + 8) = r1
; if ((entry = map_lookup_elem(map, tuple))) {
     523:	goto +11 <LBB2_32>

LBB2_31:
     524:	*(u64 *)(r10 - 160) = r7
     525:	r1 = 1
     526:	*(u64 *)(r10 - 168) = r1
     527:	r2 = r10
     528:	r2 += -24
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     529:	r3 = r10
     530:	r3 += -168
     531:	r1 = 0 ll
; uint32_t hash = get_hash_recalc(skb);
     533:	r4 = 0
     534:	call 2

LBB2_32:
; struct debug_msg msg = {
     535:	r1 = r6
     536:	r2 = 0 ll
     538:	r3 = 1
     539:	call 12
     540:	r9 = 2

LBB2_33:
     541:	r0 = r9
     542:	exit
Disassembly of section 2/4:
tail_icmp6_handle_ns:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = *(u32 *)(r6 + 52)
       2:	*(u64 *)(r10 - 144) = r1
       3:	r7 = *(u32 *)(r6 + 48)
       4:	r2 = r7
; struct lb6_key key = {};
       5:	r2 += 48
       6:	r3 = r10
       7:	r3 += -136
       8:	r1 = r6
       9:	r4 = 16
; tmp = a->p1 - b->p1;
      10:	call 26
; if (!tmp)
      11:	r9 = 4294967162 ll
      13:	r0 <<= 32
; tmp = a->p2 - b->p2;
      14:	r0 s>>= 32
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	if r0 s< 0 goto +300 <LBB3_23>
      16:	r8 = *(u64 *)(r10 - 128)
      17:	r1 = r6
; tmp = a->p1 - b->p1;
      18:	call 34
; if (!tmp)
      19:	*(u32 *)(r10 - 20) = r0
      20:	r1 = 269487362
      21:	*(u32 *)(r10 - 24) = r1
; tmp = a->p2 - b->p2;
      22:	*(u64 *)(r10 - 16) = r8
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r1 = 0
      24:	*(u32 *)(r10 - 8) = r1
      25:	r4 = r10
; tmp = a->p1 - b->p1;
      26:	r4 += -24
; if (!tmp) {
      27:	r1 = r6
; tmp = a->p2 - b->p2;
      28:	r2 = 0 ll
; tmp = a->p3 - b->p3;
      30:	r3 = 4294967295 ll
; tmp = a->p4 - b->p4;
      32:	r5 = 20
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	call 25
      34:	r9 = 4294967146 ll
      36:	r1 = *(u32 *)(r10 - 136)
; dst->p1 = src->p1;
      37:	if r1 != 61374 goto +278 <LBB3_23>
      38:	r1 = *(u32 *)(r10 - 132)
; dst->p2 = src->p2;
      39:	if r1 != 0 goto +276 <LBB3_23>
      40:	r1 = *(u32 *)(r10 - 128)
; dst->p3 = src->p3;
      41:	if r1 != 16777216 goto +274 <LBB3_23>
      42:	r1 = *(u32 *)(r10 - 124)
; dst->p4 = src->p4;
      43:	if r1 != 256 goto +272 <LBB3_23>
      44:	r1 = 0
; dst->p1 = src->p1;
      45:	*(u64 *)(r10 - 96) = r1
      46:	r8 = r7
; dst->p2 = src->p2;
      47:	r8 += 40
      48:	r3 = r10
; dst->p3 = src->p3;
      49:	r3 += -104
      50:	r1 = r6
; dst->p4 = src->p4;
      51:	r2 = r8
      52:	r4 = 8
      53:	call 26
      54:	r0 <<= 32
; __u8 nh = *nexthdr;
      55:	r0 s>>= 32
; switch (nh) {
      56:	r9 = 4294967162 ll
      58:	if r0 s< 0 goto +257 <LBB3_23>
      59:	r1 = 136
      60:	*(u16 *)(r10 - 96) = r1
      61:	r1 = *(u16 *)(r10 - 102)
      62:	*(u16 *)(r10 - 94) = r1
      63:	r1 = 192
      64:	*(u32 *)(r10 - 92) = r1
      65:	r3 = r10
      66:	r3 += -96
      67:	r1 = r6
      68:	r2 = r8
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r4 = 8
      70:	r5 = 0
      71:	call 9
      72:	r0 <<= 32
      73:	r0 s>>= 32
      74:	r9 = 4294967155 ll
      76:	if r0 s< 0 goto +239 <LBB3_23>
      77:	r8 = r7
      78:	r8 += 42
      79:	r1 = r10
; nh = opthdr.nexthdr;
      80:	r1 += -104
; if (nh == NEXTHDR_AUTH)
      81:	r3 = r10
      82:	r3 += -96
      83:	r2 = 8
      84:	r4 = 8
      85:	r5 = 0
      86:	call 28
; switch (nh) {
      87:	r1 = r6
      88:	*(u64 *)(r10 - 152) = r8
      89:	r2 = r8
      90:	r3 = 0
      91:	r4 = r0
      92:	r5 = 16
      93:	call 11
      94:	r0 <<= 32
      95:	r0 s>>= 32
      96:	r9 = 4294967142 ll
      98:	if r0 s< 0 goto +217 <LBB3_23>
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r8 = r7
     100:	r8 += 64
     101:	r3 = r10
     102:	r3 += -120
     103:	r1 = r6
     104:	r2 = r8
     105:	r4 = 8
     106:	call 26
     107:	r0 <<= 32
     108:	r0 s>>= 32
     109:	r9 = 4294967162 ll
; if (nh == NEXTHDR_AUTH)
     111:	if r0 s< 0 goto +204 <LBB3_23>
     112:	r1 = 1
     113:	*(u8 *)(r10 - 111) = r1
     114:	r1 = 2
     115:	*(u8 *)(r10 - 112) = r1
     116:	r1 = 173
     117:	*(u8 *)(r10 - 109) = r1
; switch (nh) {
     118:	r1 = 190
     119:	*(u8 *)(r10 - 108) = r1
     120:	r1 = 239
     121:	*(u8 *)(r10 - 107) = r1
     122:	r1 = 192
     123:	*(u8 *)(r10 - 106) = r1
     124:	r1 = 222
     125:	*(u8 *)(r10 - 110) = r1
     126:	*(u8 *)(r10 - 105) = r1
     127:	r3 = r10
     128:	r3 += -112
     129:	r1 = r6
     130:	r2 = r8
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r4 = 8
     132:	r5 = 0
     133:	call 9
     134:	r0 <<= 32
     135:	r0 s>>= 32
     136:	r9 = 4294967155 ll
     138:	if r0 s< 0 goto +177 <LBB3_23>
     139:	r1 = r10
     140:	r1 += -120
     141:	r3 = r10
; nh = opthdr.nexthdr;
     142:	r3 += -112
; if (nh == NEXTHDR_AUTH)
     143:	r2 = 8
     144:	r4 = 8
     145:	r5 = 0
     146:	call 28
     147:	r1 = r6
     148:	r2 = *(u64 *)(r10 - 152)
     149:	r3 = 0
; switch (nh) {
     150:	r4 = r0
     151:	r5 = 16
     152:	call 11
     153:	r0 <<= 32
     154:	r0 s>>= 32
     155:	r9 = 4294967142 ll
     157:	if r0 s< 0 goto +158 <LBB3_23>
     158:	r1 = 244920237338078 ll
     160:	*(u64 *)(r10 - 40) = r1
     161:	r8 = r7
     162:	r8 += 8
; *nexthdr = nh;
     163:	r3 = r10
; dst->p1 = src->p1;
     164:	r3 += -56
     165:	r1 = r6
; dst->p2 = src->p2;
     166:	r2 = r8
     167:	r4 = 16
; dst->p3 = src->p3;
     168:	call 26
     169:	r0 <<= 32
; dst->p4 = src->p4;
     170:	r0 s>>= 32
     171:	r9 = 4294967162 ll
     173:	if r0 s< 0 goto +142 <LBB3_23>
     174:	r7 += 24
; switch (nexthdr) {
     175:	r3 = r10
     176:	r3 += -72
     177:	r1 = r6
     178:	r2 = r7
     179:	r4 = 16
     180:	call 26
     181:	r0 <<= 32
     182:	r0 s>>= 32
     183:	r9 = 4294967162 ll
; }
     185:	if r0 s< 0 goto +130 <LBB3_23>
     186:	r1 = 61374
; switch (nexthdr) {
     187:	*(u64 *)(r10 - 88) = r1
     188:	r1 = 1099528404992 ll
     190:	*(u64 *)(r10 - 80) = r1
     191:	r3 = r10
     192:	r3 += -88
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r1 = r6
     194:	r2 = r8
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r4 = 16
     196:	r5 = 0
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	call 9
     198:	r0 <<= 32
     199:	r0 s>>= 32
     200:	r9 = 4294967155 ll
     202:	if r0 s< 0 goto +113 <LBB3_23>
     203:	r3 = r10
; if (IS_ERR(ret))
     204:	r3 += -56
     205:	r1 = r6
     206:	r2 = r7
     207:	r4 = 16
     208:	r5 = 0
     209:	call 9
     210:	r0 <<= 32
     211:	r0 s>>= 32
     212:	r9 = 4294967155 ll
; if (IS_ERR(ret)) {
     214:	if r0 s< 0 goto +101 <LBB3_23>
     215:	r1 = r10
     216:	r1 += -56
     217:	r3 = r10
     218:	r3 += -88
     219:	r2 = 16
     220:	r4 = 16
     221:	r5 = 0
     222:	call 28
     223:	r1 = r6
     224:	r2 = *(u64 *)(r10 - 152)
     225:	r3 = 0
     226:	r4 = r0
     227:	r5 = 16
; if (ret == DROP_UNKNOWN_L4)
     228:	call 11
     229:	r9 = 4294967142 ll
     231:	r0 <<= 32
     232:	r0 s>>= 32
     233:	if r0 s< 0 goto +82 <LBB3_23>
     234:	r1 = r10
     235:	r1 += -72
     236:	r3 = r10
     237:	r3 += -56
     238:	r2 = 16
     239:	r4 = 16
     240:	r5 = 0
; if (key->dport) {
     241:	call 28
     242:	r1 = r6
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r2 = *(u64 *)(r10 - 152)
; uint32_t hash = get_hash_recalc(skb);
     244:	r3 = 0
     245:	r4 = r0
; struct debug_msg msg = {
     246:	r5 = 16
     247:	call 11
     248:	r0 <<= 32
     249:	r0 s>>= 32
     250:	if r0 s< 0 goto +65 <LBB3_23>
     251:	r3 = r10
     252:	r3 += -32
     253:	r1 = r6
     254:	r2 = 6
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	r4 = 6
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	call 26
     257:	r0 <<= 32
     258:	r0 s>>= 32
     259:	r9 = 4294967162 ll
     261:	if r0 s< 0 goto +54 <LBB3_23>
     262:	r3 = r10
     263:	r3 += -32
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r1 = r6
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	r2 = 0
     266:	r4 = 6
     267:	r5 = 0
; if (svc && svc->count != 0)
     268:	call 9
     269:	r0 <<= 32
     270:	r0 s>>= 32
     271:	r9 = 4294967155 ll
     273:	if r0 s< 0 goto +42 <LBB3_23>
; key->dport = 0;
     274:	r3 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r3 += -40
; uint32_t hash = get_hash_recalc(skb);
     276:	r1 = r6
     277:	r2 = 6
; struct debug_msg msg = {
     278:	r4 = 6
     279:	r5 = 0
     280:	call 9
     281:	r0 <<= 32
     282:	r0 s>>= 32
     283:	r9 = 4294967155 ll
     285:	if r0 s< 0 goto +30 <LBB3_23>
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r7 = *(u32 *)(r6 + 0)
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r8 = *(u32 *)(r6 + 40)
     288:	r1 = r6
     289:	call 34
     290:	*(u32 *)(r10 - 20) = r0
     291:	r1 = 269485059
     292:	*(u32 *)(r10 - 24) = r1
     293:	*(u32 *)(r10 - 8) = r8
     294:	*(u32 *)(r10 - 16) = r7
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	if r7 < 128 goto +1 <LBB3_22>
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r7 = 128

LBB3_22:
     297:	*(u32 *)(r10 - 12) = r7
     298:	r7 <<= 32
; if (svc && svc->count != 0)
     299:	r1 = 4294967295 ll
     301:	r7 |= r1
     302:	r1 = 0
     303:	*(u32 *)(r10 - 4) = r1
     304:	r4 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r4 += -24
     306:	r1 = r6
; uint32_t hash = get_hash_recalc(skb);
     307:	r2 = 0 ll
; struct debug_msg msg = {
     309:	r3 = r7
     310:	r5 = 24
     311:	call 25
     312:	r1 = *(u32 *)(r6 + 40)
     313:	r2 = 0
     314:	call 23
     315:	r9 = r0

LBB3_23:
     316:	r1 = r9
     317:	r1 <<= 32
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	r1 >>= 32
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r2 = 1
     320:	if r1 == 2 goto +1 <LBB3_25>
     321:	r2 = 0

LBB3_25:
     322:	r1 >>= 31
     323:	r1 |= r2
     324:	if r1 == 0 goto +46 <LBB3_30>
     325:	r1 = 2
     326:	*(u32 *)(r6 + 48) = r1
     327:	r1 = 0
     328:	*(u32 *)(r6 + 52) = r1
     329:	*(u32 *)(r6 + 56) = r9
     330:	*(u32 *)(r6 + 60) = r1
     331:	*(u32 *)(r6 + 64) = r1
     332:	r7 = *(u32 *)(r6 + 0)
; __u8 flags = tuple->flags;
     333:	*(u64 *)(r10 - 16) = r1
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	*(u64 *)(r10 - 24) = r1
; union tcp_flags tcp_flags = { 0 };
     335:	*(u64 *)(r10 - 56) = r1
     336:	r1 = *(u64 *)(r10 - 144)
; tuple->flags = TUPLE_F_SERVICE;
     337:	r1 &= 3
     338:	*(u8 *)(r10 - 55) = r1
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r9 = -r9
     340:	*(u8 *)(r10 - 56) = r9
     341:	r2 = r10
     342:	r2 += -56
     343:	r1 = 0 ll
; switch (tuple->nexthdr) {
     345:	call 1
     346:	if r0 == 0 goto +7 <LBB3_28>
     347:	r1 = *(u64 *)(r0 + 0)
     348:	r1 += 1
     349:	*(u64 *)(r0 + 0) = r1
     350:	r1 = *(u64 *)(r0 + 8)
; __u8 type;
     351:	r1 += r7
     352:	*(u64 *)(r0 + 8) = r1
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	goto +11 <LBB3_29>

LBB3_28:
     354:	*(u64 *)(r10 - 16) = r7
     355:	r1 = 1
     356:	*(u64 *)(r10 - 24) = r1
     357:	r2 = r10
     358:	r2 += -56
     359:	r3 = r10
     360:	r3 += -24
     361:	r1 = 0 ll
; tuple->dport = 0;
     363:	r4 = 0
; tuple->sport = 0;
     364:	call 2

LBB3_29:
     365:	r1 = r6
     366:	r2 = 0 ll
; switch (type) {
     368:	r3 = 1
     369:	call 12
     370:	r9 = 2

LBB3_30:
     371:	r0 = r9
     372:	exit
Disassembly of section 2/10:
tail_handle_ipv6:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 0
       2:	*(u32 *)(r10 - 68) = r1
       3:	*(u16 *)(r10 - 28) = r1
       4:	*(u32 *)(r10 - 32) = r1
; struct lb6_key key = {};
       5:	*(u64 *)(r10 - 40) = r1
       6:	*(u64 *)(r10 - 48) = r1
       7:	*(u64 *)(r10 - 56) = r1
       8:	*(u64 *)(r10 - 64) = r1
       9:	r0 = 4294967162 ll
; if (!tmp)
      11:	r1 = *(u32 *)(r6 + 80)
      12:	r7 = *(u32 *)(r6 + 76)
      13:	r2 = r7
; tmp = a->p2 - b->p2;
      14:	r2 += 54
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	if r2 > r1 goto +68 <LBB4_13>
      16:	r2 = *(u8 *)(r7 + 20)
      17:	if r2 != 58 goto +55 <LBB4_12>
; tmp = a->p1 - b->p1;
      18:	r2 = r7
; if (!tmp)
      19:	r2 += 62
      20:	if r2 > r1 goto +63 <LBB4_13>
      21:	r0 = *(u8 *)skb[54]
; tmp = a->p2 - b->p2;
      22:	r8 = r0
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r1 = r6
      24:	call 34
      25:	*(u32 *)(r10 - 20) = r0
; tmp = a->p1 - b->p1;
      26:	r1 = 269486850
; if (!tmp) {
      27:	*(u32 *)(r10 - 24) = r1
; tmp = a->p2 - b->p2;
      28:	r1 = 0
; if (!tmp) {
      29:	*(u32 *)(r10 - 12) = r1
; tmp = a->p3 - b->p3;
      30:	*(u32 *)(r10 - 8) = r1
; if (!tmp)
      31:	r8 &= 255
; tmp = a->p4 - b->p4;
      32:	*(u32 *)(r10 - 16) = r8
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r4 = r10
      34:	r4 += -24
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r1 = r6
      36:	r2 = 0 ll
; dst->p1 = src->p1;
      38:	r3 = 4294967295 ll
; dst->p2 = src->p2;
      40:	r5 = 20
; dst->p3 = src->p3;
      41:	call 25
      42:	if r8 == 128 goto +13 <LBB4_7>
; dst->p4 = src->p4;
      43:	if r8 != 135 goto +29 <LBB4_12>
      44:	r1 = 2
; dst->p1 = src->p1;
      45:	*(u32 *)(r6 + 52) = r1
      46:	r1 = 14
; dst->p2 = src->p2;
      47:	*(u32 *)(r6 + 48) = r1
      48:	r1 = r6
; dst->p3 = src->p3;
      49:	r2 = 0 ll
; dst->p4 = src->p4;
      51:	r3 = 4

LBB4_6:
      52:	call 12
      53:	r0 = 4294967156 ll
; __u8 nh = *nexthdr;
      55:	goto +28 <LBB4_13>

LBB4_7:
; switch (nh) {
      56:	r1 = *(u32 *)(r7 + 38)
      57:	if r1 != 61374 goto +15 <LBB4_12>
      58:	r1 = *(u32 *)(r7 + 42)
      59:	if r1 != 0 goto +13 <LBB4_12>
      60:	r1 = *(u32 *)(r7 + 46)
      61:	if r1 != 16777216 goto +11 <LBB4_12>
      62:	r1 = *(u32 *)(r7 + 50)
      63:	if r1 != 256 goto +9 <LBB4_12>
      64:	r1 = 2
      65:	*(u32 *)(r6 + 52) = r1
      66:	r1 = 14
      67:	*(u32 *)(r6 + 48) = r1
      68:	r1 = r6
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r2 = 0 ll
      71:	r3 = 3
      72:	goto -21 <LBB4_6>

LBB4_12:
      73:	r4 = r7
      74:	r4 += 14
      75:	r1 = *(u8 *)(r7 + 20)
      76:	*(u8 *)(r10 - 28) = r1
      77:	r2 = r10
      78:	r2 += -64
      79:	r5 = r10
; nh = opthdr.nexthdr;
      80:	r5 += -68
; if (nh == NEXTHDR_AUTH)
      81:	r1 = r6
      82:	r3 = r7
      83:	call -1

LBB4_13:
      84:	r1 = r0
      85:	r1 <<= 32
      86:	r1 >>= 32
; switch (nh) {
      87:	r2 = 1
      88:	if r1 == 2 goto +1 <LBB4_15>
      89:	r2 = 0

LBB4_15:
      90:	r1 >>= 31
      91:	r1 |= r2
      92:	if r1 == 0 goto +46 <LBB4_20>
      93:	r1 = *(u16 *)(r10 - 68)
      94:	r2 = 2
      95:	*(u32 *)(r6 + 48) = r2
      96:	r1 |= 131072
      97:	*(u32 *)(r6 + 52) = r1
      98:	*(u32 *)(r6 + 56) = r0
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r1 = 0
     100:	*(u32 *)(r6 + 60) = r1
     101:	*(u32 *)(r6 + 64) = r1
     102:	r7 = *(u32 *)(r6 + 0)
     103:	*(u64 *)(r10 - 56) = r1
     104:	*(u64 *)(r10 - 64) = r1
     105:	r1 = 512
     106:	*(u64 *)(r10 - 24) = r1
     107:	r0 = -r0
     108:	*(u8 *)(r10 - 24) = r0
     109:	r2 = r10
; nh = opthdr.nexthdr;
     110:	r2 += -24
; if (nh == NEXTHDR_AUTH)
     111:	r1 = 0 ll
     113:	call 1
     114:	if r0 == 0 goto +7 <LBB4_18>
     115:	r1 = *(u64 *)(r0 + 0)
     116:	r1 += 1
     117:	*(u64 *)(r0 + 0) = r1
; switch (nh) {
     118:	r1 = *(u64 *)(r0 + 8)
     119:	r1 += r7
     120:	*(u64 *)(r0 + 8) = r1
     121:	goto +11 <LBB4_19>

LBB4_18:
     122:	*(u64 *)(r10 - 56) = r7
     123:	r1 = 1
     124:	*(u64 *)(r10 - 64) = r1
     125:	r2 = r10
     126:	r2 += -24
     127:	r3 = r10
     128:	r3 += -64
     129:	r1 = 0 ll
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r4 = 0
     132:	call 2

LBB4_19:
     133:	r1 = r6
     134:	r2 = 0 ll
     136:	r3 = 1
     137:	call 12
     138:	r0 = 2

LBB4_20:
     139:	exit
Disassembly of section 2/7:
tail_handle_ipv4:
; {
       0:	r9 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 0
       2:	*(u16 *)(r10 - 108) = r1
       3:	*(u32 *)(r10 - 112) = r1
       4:	*(u64 *)(r10 - 120) = r1
; struct lb6_key key = {};
       5:	r2 = 244920237338078 ll
       7:	*(u64 *)(r10 - 128) = r2
       8:	*(u64 *)(r10 - 136) = r1
       9:	*(u64 *)(r10 - 144) = r1
; tmp = a->p1 - b->p1;
      10:	*(u64 *)(r10 - 152) = r1
; if (!tmp)
      11:	*(u64 *)(r10 - 160) = r1
      12:	r1 = *(u32 *)(r9 + 80)
      13:	r8 = *(u32 *)(r9 + 76)
; tmp = a->p2 - b->p2;
      14:	r2 = r8
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r2 += 34
      16:	r4 = 0
      17:	r7 = 4294967162 ll
; if (!tmp)
      19:	if r2 > r1 goto +3428 <LBB5_373>
      20:	r7 = 4294967166 ll
; tmp = a->p2 - b->p2;
      22:	r1 = *(u8 *)(r8 + 23)
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	*(u8 *)(r10 - 108) = r1
      24:	r2 = *(u32 *)(r8 + 6)
      25:	r3 = 3721182122 ll
; if (!tmp) {
      27:	r4 = 0
; tmp = a->p2 - b->p2;
      28:	if r2 != r3 goto +3419 <LBB5_373>
; if (!tmp) {
      29:	r2 = *(u16 *)(r8 + 10)
; tmp = a->p3 - b->p3;
      30:	r4 = 0
; if (!tmp)
      31:	if r2 != 65518 goto +3416 <LBB5_373>
; tmp = a->p4 - b->p4;
      32:	r7 = 4294967165 ll
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      34:	r2 = *(u32 *)(r8 + 0)
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r3 = 4022250974 ll
; dst->p1 = src->p1;
      37:	r4 = 0
      38:	if r2 != r3 goto +3409 <LBB5_373>
; dst->p2 = src->p2;
      39:	r2 = *(u16 *)(r8 + 4)
      40:	r4 = 0
; dst->p3 = src->p3;
      41:	if r2 != 57024 goto +3406 <LBB5_373>
      42:	r7 = 4294967164 ll
; dst->p4 = src->p4;
      44:	r2 = *(u32 *)(r8 + 26)
; dst->p1 = src->p1;
      45:	r4 = 0
      46:	if r2 != 270544960 goto +3401 <LBB5_373>
; dst->p2 = src->p2;
      47:	r2 = *(u32 *)(r8 + 30)
      48:	r3 = 270544960
; dst->p3 = src->p3;
      49:	*(u32 *)(r10 - 116) = r3
      50:	*(u32 *)(r10 - 120) = r2
; dst->p4 = src->p4;
      51:	r6 = *(u8 *)(r8 + 14)
      52:	*(u32 *)(r10 - 136) = r2
      53:	r7 = 4294967154 ll
; __u8 nh = *nexthdr;
      55:	r2 = 0
; switch (nh) {
      56:	*(u64 *)(r10 - 232) = r2
      57:	r6 <<= 2
      58:	r6 &= 60
      59:	r6 += 14
      60:	*(u64 *)(r10 - 192) = r9
      61:	if r1 s> 16 goto +6 <LBB5_9>
      62:	r9 = 0
      63:	if r1 == 1 goto +28 <LBB5_15>
      64:	r9 = 16
      65:	r2 = 0
      66:	if r1 == 6 goto +7 <LBB5_12>
      67:	goto +26 <LBB5_16>

LBB5_9:
      68:	if r1 == 58 goto +148 <LBB5_38>
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r2 = 0
      70:	if r1 != 17 goto +23 <LBB5_16>
      71:	r9 = 6
      72:	r1 = 32
      73:	*(u64 *)(r10 - 232) = r1

LBB5_12:
      74:	r2 = r6
      75:	r2 += 2
      76:	r3 = r10
      77:	r3 += -132
      78:	r1 = *(u64 *)(r10 - 192)
      79:	r4 = 2
; nh = opthdr.nexthdr;
      80:	call 26
; if (nh == NEXTHDR_AUTH)
      81:	r7 = r0
      82:	r1 = r7
      83:	r1 <<= 32
      84:	r1 >>= 32
      85:	r2 = 1
      86:	if r1 == 2 goto +1 <LBB5_14>
; switch (nh) {
      87:	r2 = 0

LBB5_14:
      88:	r1 >>= 31
      89:	r1 |= r2
      90:	r2 = r9
      91:	if r1 != 0 goto +2 <LBB5_16>

LBB5_15:
      92:	r7 = 0
      93:	r2 = r9

LBB5_16:
      94:	*(u64 *)(r10 - 256) = r2
      95:	r1 = r7
      96:	r1 <<= 32
      97:	r1 >>= 32
      98:	r2 = 1
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	if r1 == 2 goto +1 <LBB5_18>
     100:	r2 = 0

LBB5_18:
     101:	r1 >>= 31
     102:	r1 |= r2
     103:	r9 = *(u64 *)(r10 - 192)
     104:	*(u64 *)(r10 - 200) = r6
     105:	if r1 == 0 goto +17 <LBB5_20>
     106:	r1 = 0
     107:	*(u64 *)(r10 - 240) = r1
     108:	r1 = r7
     109:	r1 <<= 32
; nh = opthdr.nexthdr;
     110:	r1 >>= 32
; if (nh == NEXTHDR_AUTH)
     111:	r2 = 4294967154 ll
     113:	r3 = 0
     114:	*(u64 *)(r10 - 272) = r3
     115:	r3 = 0
     116:	*(u64 *)(r10 - 224) = r3
     117:	r3 = 0
; switch (nh) {
     118:	*(u64 *)(r10 - 288) = r3
     119:	r8 = 0
     120:	r4 = 0
     121:	if r1 == r2 goto +374 <LBB5_72>
     122:	goto +3325 <LBB5_373>

LBB5_20:
     123:	r1 = *(u16 *)(r10 - 132)
     124:	if r1 == 0 goto +13 <LBB5_24>
     125:	r2 = r10
     126:	r2 += -136
     127:	r1 = 0 ll
     129:	call 1
     130:	if r0 == 0 goto +5 <LBB5_23>
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r1 = *(u8 *)(r0 + 6)
     132:	r2 = *(u8 *)(r0 + 7)
     133:	r2 <<= 8
     134:	r2 |= r1
     135:	if r2 != 0 goto +40 <LBB5_27>

LBB5_23:
     136:	r1 = 0
     137:	*(u16 *)(r10 - 132) = r1

LBB5_24:
     138:	r2 = r10
     139:	r2 += -136
     140:	r1 = 0 ll
; nh = opthdr.nexthdr;
     142:	call 1
; if (nh == NEXTHDR_AUTH)
     143:	if r0 == 0 goto +5 <LBB5_26>
     144:	r1 = *(u8 *)(r0 + 6)
     145:	r2 = *(u8 *)(r0 + 7)
     146:	r2 <<= 8
     147:	r2 |= r1
     148:	if r2 != 0 goto +27 <LBB5_27>

LBB5_26:
     149:	r1 = r9
; switch (nh) {
     150:	call 34
     151:	*(u32 *)(r10 - 100) = r0
     152:	r1 = 269491458
     153:	*(u32 *)(r10 - 104) = r1
     154:	r2 = 0
     155:	*(u64 *)(r10 - 96) = r2
     156:	r1 = 0
     157:	*(u64 *)(r10 - 240) = r1
     158:	*(u32 *)(r10 - 88) = r2
     159:	r4 = r10
     160:	r4 += -104
     161:	r1 = r9
     162:	r2 = 0 ll
; dst->p1 = src->p1;
     164:	r3 = 4294967295 ll
; dst->p2 = src->p2;
     166:	r5 = 20
     167:	call 25
; dst->p3 = src->p3;
     168:	r1 = 0
     169:	*(u64 *)(r10 - 272) = r1
; dst->p4 = src->p4;
     170:	r1 = 0
     171:	*(u64 *)(r10 - 224) = r1
     172:	r1 = 0
     173:	*(u64 *)(r10 - 288) = r1
     174:	r8 = 0
; switch (nexthdr) {
     175:	goto +320 <LBB5_72>

LBB5_27:
     176:	r1 = *(u32 *)(r8 + 26)
     177:	r8 = *(u8 *)(r10 - 108)
     178:	*(u32 *)(r10 - 184) = r1
     179:	r7 = 0 ll
     181:	if r8 == 6 goto +2 <LBB5_29>
     182:	r7 = 0 ll

LBB5_29:
     184:	r1 = 0
; }
     185:	*(u32 *)(r10 - 8) = r1
     186:	r3 = *(u8 *)(r10 - 107)
; switch (nexthdr) {
     187:	r2 = 4
     188:	*(u8 *)(r10 - 107) = r2
     189:	*(u16 *)(r10 - 40) = r1
     190:	*(u64 *)(r10 - 208) = r3
     191:	*(u64 *)(r10 - 248) = r0
     192:	if r8 == 17 goto +63 <LBB5_45>
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	if r8 == 6 goto +25 <LBB5_39>
     194:	if r8 != 1 goto +277 <LBB5_66>
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r3 = r10
     196:	r3 += -104
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r1 = 1
     198:	*(u64 *)(r10 - 240) = r1
     199:	r1 = r9
     200:	r2 = r6
     201:	r4 = 1
     202:	call 26
     203:	r0 <<= 32
; if (IS_ERR(ret))
     204:	r0 s>>= 32
     205:	if r0 s< 0 goto +266 <LBB5_66>
     206:	r1 = 0
     207:	*(u32 *)(r10 - 112) = r1
     208:	r1 = *(u8 *)(r10 - 104)
     209:	if r1 s> 10 goto +35 <LBB5_41>
     210:	if r1 == 0 goto +40 <LBB5_43>
     211:	if r1 == 3 goto +35 <LBB5_42>
     212:	if r1 == 8 goto +1 <LBB5_37>
     213:	goto +53 <LBB5_46>

LBB5_37:
; if (IS_ERR(ret)) {
     214:	r1 = 8
     215:	*(u16 *)(r10 - 110) = r1
     216:	goto +50 <LBB5_46>

LBB5_38:
     217:	r9 = 2
     218:	goto -127 <LBB5_15>

LBB5_39:
     219:	r2 = r6
     220:	r2 += 12
     221:	r3 = r10
     222:	r3 += -40
     223:	r1 = r9
     224:	r4 = 2
     225:	call 26
     226:	r0 <<= 32
     227:	r0 s>>= 32
; if (ret == DROP_UNKNOWN_L4)
     228:	if r0 s< 0 goto +243 <LBB5_66>
     229:	*(u64 *)(r10 - 216) = r7
     230:	r7 = *(u8 *)(r10 - 40)
     231:	r3 = r10
     232:	r3 += -112
     233:	r1 = r9
     234:	r2 = r6
     235:	r4 = 4
     236:	call 26
     237:	r7 &= 1
     238:	r7 += 1
     239:	*(u64 *)(r10 - 240) = r7
     240:	r7 = *(u64 *)(r10 - 216)
; if (key->dport) {
     241:	r0 <<= 32
     242:	r0 s>>= 32
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	if r0 s< 0 goto +228 <LBB5_66>
; uint32_t hash = get_hash_recalc(skb);
     244:	goto +22 <LBB5_46>

LBB5_41:
     245:	r1 += -11
; struct debug_msg msg = {
     246:	if r1 > 1 goto +20 <LBB5_46>

LBB5_42:
     247:	r1 = *(u8 *)(r10 - 107)
     248:	r1 |= 2
     249:	*(u8 *)(r10 - 107) = r1
     250:	goto +2 <LBB5_44>

LBB5_43:
     251:	r1 = 8
     252:	*(u16 *)(r10 - 112) = r1

LBB5_44:
     253:	r1 = 0
     254:	*(u64 *)(r10 - 240) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	goto +11 <LBB5_46>

LBB5_45:
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r3 = r10
     257:	r3 += -112
     258:	r1 = r9
     259:	r2 = r6
     260:	r4 = 4
     261:	call 26
     262:	r1 = 1
     263:	*(u64 *)(r10 - 240) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r0 <<= 32
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	r0 s>>= 32
     266:	if r0 s< 0 goto +205 <LBB5_66>

LBB5_46:
     267:	*(u64 *)(r10 - 216) = r7
; if (svc && svc->count != 0)
     268:	*(u64 *)(r10 - 272) = r8
     269:	r6 = *(u16 *)(r10 - 112)
     270:	r7 = *(u16 *)(r10 - 110)
     271:	r8 = *(u32 *)(r10 - 120)
     272:	r9 = *(u32 *)(r10 - 116)
     273:	r1 = *(u64 *)(r10 - 192)
; key->dport = 0;
     274:	call 34
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	*(u32 *)(r10 - 100) = r0
; uint32_t hash = get_hash_recalc(skb);
     276:	r1 = 269495298
     277:	*(u32 *)(r10 - 104) = r1
; struct debug_msg msg = {
     278:	*(u32 *)(r10 - 96) = r9
     279:	r9 = *(u64 *)(r10 - 192)
     280:	*(u32 *)(r10 - 92) = r8
     281:	r7 = be32 r7
     282:	r1 = 4294901760 ll
     284:	r7 &= r1
     285:	r6 = be16 r6
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r7 |= r6
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	*(u32 *)(r10 - 88) = r7
     288:	r4 = r10
     289:	r4 += -104
     290:	r1 = r9
     291:	r2 = 0 ll
     293:	r3 = 4294967295 ll
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	r5 = 20
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	call 25
     297:	r6 = *(u8 *)(r10 - 107)
     298:	r7 = *(u8 *)(r10 - 108)
; if (svc && svc->count != 0)
     299:	r1 = r9
     300:	call 34
     301:	*(u32 *)(r10 - 100) = r0
     302:	r1 = 269495554
     303:	*(u32 *)(r10 - 104) = r1
     304:	r7 <<= 8
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r7 |= r6
     306:	*(u32 *)(r10 - 96) = r7
; uint32_t hash = get_hash_recalc(skb);
     307:	r1 = 0
     308:	*(u32 *)(r10 - 92) = r1
; struct debug_msg msg = {
     309:	*(u32 *)(r10 - 88) = r1
     310:	r4 = r10
     311:	r4 += -104
     312:	r1 = r9
     313:	r2 = 0 ll
     315:	r3 = 4294967295 ll
     317:	r5 = 20
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	call 25
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r1 = *(u8 *)(r10 - 39)
     320:	*(u64 *)(r10 - 280) = r1
     321:	r1 = *(u8 *)(r10 - 40)
     322:	*(u64 *)(r10 - 288) = r1
     323:	r2 = r10
     324:	r2 += -120
     325:	r1 = *(u64 *)(r10 - 216)
     326:	call 1
     327:	r7 = r0
     328:	r6 = 0
     329:	r4 = 0
     330:	r1 = 0
     331:	*(u64 *)(r10 - 224) = r1
     332:	r8 = 0
; __u8 flags = tuple->flags;
     333:	if r7 == 0 goto +276 <LBB5_93>
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	r6 = *(u16 *)(r7 + 38)
; union tcp_flags tcp_flags = { 0 };
     335:	r8 = *(u32 *)(r7 + 32)
     336:	r1 = r9
; tuple->flags = TUPLE_F_SERVICE;
     337:	call 34
     338:	*(u32 *)(r10 - 100) = r0
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r1 = 269486082
     340:	*(u32 *)(r10 - 104) = r1
     341:	*(u32 *)(r10 - 96) = r8
     342:	*(u32 *)(r10 - 92) = r6
     343:	r1 = 0
     344:	*(u32 *)(r10 - 88) = r1
; switch (tuple->nexthdr) {
     345:	r4 = r10
     346:	r4 += -104
     347:	r1 = r9
     348:	r2 = 0 ll
     350:	r3 = 4294967295 ll
     352:	r5 = 20
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	call 25
     354:	r1 = *(u16 *)(r7 + 36)
     355:	r2 = r1
     356:	r2 &= 3
     357:	r8 = *(u64 *)(r10 - 272)
     358:	if r2 == 3 goto +39 <LBB5_54>
     359:	r6 = 60
     360:	if r8 != 6 goto +16 <LBB5_51>
     361:	r2 = *(u64 *)(r10 - 288)
; tuple->dport = 0;
     362:	r2 ^= 1
     363:	r2 &= 255
; tuple->sport = 0;
     364:	r3 = r1
     365:	r3 >>= 4
     366:	r3 |= r2
; switch (type) {
     367:	r2 = r3
     368:	r2 <<= 4
     369:	r2 &= 16
     370:	r1 &= 65519
     371:	r2 |= r1
     372:	*(u16 *)(r7 + 36) = r2
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r3 &= 1
     374:	r6 = 60
     375:	if r3 == 0 goto +1 <LBB5_51>
     376:	r6 = 21600

LBB5_51:
     377:	call 5
     378:	r0 /= 1000000000
     379:	r6 += r0
     380:	*(u32 *)(r7 + 32) = r6
     381:	r2 = *(u8 *)(r7 + 42)
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	r1 = r2
     383:	r3 = *(u64 *)(r10 - 280)
     384:	r1 |= r3
     385:	r3 = r1
     386:	r3 &= 255
     387:	if r2 != r3 goto +8 <LBB5_53>
     388:	r2 = *(u32 *)(r7 + 48)
     389:	r2 += 5
     390:	r3 = r0
     391:	r3 <<= 32
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     392:	r3 >>= 32
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	r2 <<= 32
     394:	r2 >>= 32
     395:	if r2 >= r3 goto +2 <LBB5_54>

LBB5_53:
     396:	*(u8 *)(r7 + 42) = r1
     397:	*(u32 *)(r7 + 48) = r0

LBB5_54:
     398:	r1 = *(u16 *)(r7 + 40)
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	*(u64 *)(r10 - 224) = r1
     400:	r6 = *(u16 *)(r7 + 38)
     401:	r4 = *(u16 *)(r7 + 36)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r1 = r4
     403:	r1 &= 4
     404:	if r1 == 0 goto +4 <LBB5_57>
     405:	r1 = *(u32 *)(r9 + 60)
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	if r1 != 0 goto +2 <LBB5_57>
     407:	r1 = 2
     408:	*(u32 *)(r9 + 60) = r1

LBB5_57:
     409:	r4 >>= 3
     410:	r1 = 1
     411:	lock *(u64 *)(r7 + 16) += r1
     412:	r1 = *(u32 *)(r9 + 0)
     413:	lock *(u64 *)(r7 + 24) += r1
     414:	r1 = *(u64 *)(r10 - 240)
     415:	if r1 == 2 goto +160 <LBB5_88>
     416:	r1 <<= 32
     417:	r1 >>= 32
     418:	if r1 != 1 goto +186 <LBB5_92>
     419:	r1 = *(u16 *)(r7 + 36)
; tuple->flags |= TUPLE_F_RELATED;
     420:	r2 = r1
     421:	r2 &= 1
     422:	r3 = r1
     423:	r3 >>= 1
; break;
     424:	r3 &= 1
     425:	r3 = -r3
; tuple->sport = type;
     426:	if r2 == r3 goto +178 <LBB5_92>
     427:	*(u64 *)(r10 - 264) = r4
     428:	r2 = r1
     429:	r2 &= 65532
     430:	*(u16 *)(r7 + 36) = r2
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	r2 = r8
     432:	r8 = 60
     433:	if r2 != 6 goto +16 <LBB5_63>
     434:	r3 = *(u64 *)(r10 - 288)
     435:	r3 ^= 1
     436:	r3 &= 255
     437:	r2 = r1
     438:	r2 >>= 4
     439:	r2 |= r3
     440:	r3 = r2
     441:	r3 <<= 4
     442:	r3 &= 16
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	r1 &= 65516
     444:	r3 |= r1
     445:	*(u16 *)(r7 + 36) = r3
     446:	r2 &= 1
     447:	r8 = 60
     448:	if r2 == 0 goto +1 <LBB5_63>
     449:	r8 = 21600

LBB5_63:
     450:	call 5
     451:	r0 /= 1000000000
     452:	r8 += r0
     453:	*(u32 *)(r7 + 32) = r8
     454:	r2 = *(u8 *)(r7 + 42)
     455:	r1 = r2
     456:	r3 = *(u64 *)(r10 - 280)
     457:	r1 |= r3
     458:	r3 = r1
     459:	r3 &= 255
     460:	r9 = *(u64 *)(r10 - 192)
     461:	r4 = *(u64 *)(r10 - 264)
     462:	if r2 != r3 goto +8 <LBB5_65>
     463:	r2 = *(u32 *)(r7 + 48)
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	r2 += 5
     465:	r3 = r0
     466:	r3 <<= 32
     467:	r3 >>= 32
     468:	r2 <<= 32
     469:	r2 >>= 32
     470:	if r2 >= r3 goto +134 <LBB5_92>

LBB5_65:
; uint32_t hash = get_hash_recalc(skb);
     471:	goto +131 <LBB5_91>

LBB5_66:
     472:	r1 = 0
; struct debug_msg msg = {
     473:	*(u64 *)(r10 - 240) = r1
     474:	r4 = 0
     475:	r1 = 0
     476:	*(u64 *)(r10 - 224) = r1

LBB5_67:
     477:	r1 = *(u64 *)(r10 - 208)
     478:	*(u8 *)(r10 - 107) = r1
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	r7 = 4294967138 ll
     481:	r1 = 0
     482:	*(u64 *)(r10 - 288) = r1
     483:	*(u64 *)(r10 - 272) = r4

LBB5_68:
     484:	r8 = 0

LBB5_69:
     485:	r1 = r7
     486:	r1 <<= 32
     487:	r1 >>= 32
; struct debug_msg msg = {
     488:	r4 = 0
     489:	r2 = 1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     490:	if r1 == 2 goto +1 <LBB5_71>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     491:	r2 = 0

LBB5_71:
     492:	r1 >>= 31
     493:	r1 |= r2
     494:	r9 = *(u64 *)(r10 - 192)
     495:	if r1 != 0 goto +2952 <LBB5_373>

LBB5_72:
     496:	r1 = *(u32 *)(r10 - 120)
     497:	*(u64 *)(r10 - 216) = r1
     498:	r2 = *(u8 *)(r10 - 108)
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     499:	r1 = 1
     500:	*(u8 *)(r10 - 107) = r1
; uint32_t hash = get_hash_recalc(skb);
     501:	r1 = 0
     502:	*(u16 *)(r10 - 40) = r1
; struct debug_msg msg = {
     503:	r1 = 0 ll
     505:	*(u64 *)(r10 - 208) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     506:	if r2 == 6 goto +3 <LBB5_74>
     507:	r1 = 0 ll
; struct debug_msg msg = {
     509:	*(u64 *)(r10 - 208) = r1

LBB5_74:
     510:	r6 = *(u64 *)(r10 - 200)
     511:	*(u64 *)(r10 - 264) = r2
     512:	if r2 == 17 goto +648 <LBB5_140>
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     513:	if r2 == 6 goto +25 <LBB5_83>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     514:	r7 = 4294967159 ll
     516:	if r2 != 1 goto +869 <LBB5_161>
     517:	r3 = r10
     518:	r3 += -104
     519:	r1 = 1
     520:	*(u64 *)(r10 - 280) = r1
     521:	r1 = r9
     522:	r2 = r6
; if ((entry = map_lookup_elem(map, tuple))) {
     523:	r4 = 1
     524:	call 26
     525:	r0 <<= 32
     526:	r0 s>>= 32
     527:	if r0 s< 0 goto +39 <LBB5_85>
     528:	r1 = 0
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     529:	*(u32 *)(r10 - 112) = r1
     530:	r1 = *(u8 *)(r10 - 104)
     531:	if r1 s> 10 goto +38 <LBB5_86>
     532:	if r1 == 0 goto +623 <LBB5_138>
; uint32_t hash = get_hash_recalc(skb);
     533:	if r1 == 3 goto +38 <LBB5_87>
     534:	if r1 == 8 goto +1 <LBB5_82>
; struct debug_msg msg = {
     535:	goto +638 <LBB5_141>

LBB5_82:
     536:	r1 = 8
     537:	*(u16 *)(r10 - 110) = r1
     538:	goto +635 <LBB5_141>

LBB5_83:
     539:	r2 = r6
     540:	r2 += 12
     541:	r3 = r10
     542:	r3 += -40
     543:	r1 = r9
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     544:	r4 = 2
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     545:	call 26
     546:	r7 = 4294967161 ll
     548:	r0 <<= 32
     549:	r0 s>>= 32
     550:	if r0 s< 0 goto +835 <LBB5_161>
     551:	*(u64 *)(r10 - 248) = r8
; return !entry->rx_closing || !entry->tx_closing;
     552:	r8 = *(u8 *)(r10 - 40)
     553:	r3 = r10
     554:	r3 += -112
; if (ct_entry_alive(entry)) {
     555:	r1 = r9
     556:	r2 = r6
; if (tcp) {
     557:	r4 = 4
     558:	call 26
; entry->seen_non_syn |= !syn;
     559:	r8 &= 1
     560:	r8 += 1
     561:	*(u64 *)(r10 - 280) = r8
     562:	r8 = *(u64 *)(r10 - 248)
     563:	r0 <<= 32
     564:	r0 s>>= 32
     565:	if r0 s< 0 goto +820 <LBB5_161>
     566:	goto +607 <LBB5_141>

LBB5_85:
     567:	r7 = 4294967161 ll
     569:	goto +816 <LBB5_161>

LBB5_86:
     570:	r1 += -11
; if (entry->seen_non_syn)
     571:	if r1 > 1 goto +602 <LBB5_141>

LBB5_87:
     572:	r1 = *(u8 *)(r10 - 107)
     573:	r1 |= 2
     574:	*(u8 *)(r10 - 107) = r1
; return ktime_get_ns();
     575:	goto +582 <LBB5_139>

LBB5_88:
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     576:	r1 = *(u16 *)(r7 + 36)
; entry->lifetime = now + lifetime;
     577:	r1 |= 2
     578:	*(u16 *)(r7 + 36) = r1
; seen_flags |= *accumulated_flags;
     579:	r1 &= 3
     580:	if r1 != 3 goto +24 <LBB5_92>
     581:	r8 = r4
     582:	call 5
     583:	r4 = r8
     584:	r0 /= 1000000000
; if (*last_report + CT_REPORT_INTERVAL < now ||
     585:	r1 = r0
     586:	r1 += 10
     587:	*(u32 *)(r7 + 32) = r1
     588:	r2 = *(u8 *)(r7 + 42)
     589:	r1 = r2
     590:	r3 = *(u64 *)(r10 - 280)
     591:	r1 |= r3
     592:	r3 = r1
     593:	r3 &= 255
; *accumulated_flags = seen_flags;
     594:	if r2 != r3 goto +8 <LBB5_91>
; *last_report = now;
     595:	r2 = *(u32 *)(r7 + 48)
; ct_state->slave = entry->slave;
     596:	r2 += 5
; ct_state->rev_nat_index = entry->rev_nat_index;
     597:	r3 = r0
     598:	r3 <<= 32
; ct_state->loopback = entry->lb_loopback;
     599:	r3 >>= 32
     600:	r2 <<= 32
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
     601:	r2 >>= 32
     602:	if r2 >= r3 goto +2 <LBB5_92>

LBB5_91:
     603:	*(u8 *)(r7 + 42) = r1
     604:	*(u32 *)(r7 + 48) = r0

LBB5_92:
     605:	r4 &= 1
; skb->cb[CB_NAT46_STATE] = NAT46;
     606:	r8 = *(u8 *)(r10 - 107)
     607:	r8 >>= 1
     608:	r8 &= 1
; __sync_fetch_and_add(&entry->tx_packets, 1);
     609:	r8 |= 2

LBB5_93:
     610:	*(u64 *)(r10 - 264) = r4
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
     611:	r1 = r9
     612:	call 34
     613:	*(u32 *)(r10 - 100) = r0
     614:	r1 = 269487874
; switch (action) {
     615:	*(u32 *)(r10 - 104) = r1
     616:	r1 = 0
     617:	*(u32 *)(r10 - 88) = r1
     618:	*(u32 *)(r10 - 96) = r8
; ret = entry->rx_closing + entry->tx_closing;
     619:	*(u64 *)(r10 - 240) = r6
     620:	r7 = r6
     621:	r7 &= 65535
     622:	*(u32 *)(r10 - 92) = r7
     623:	r4 = r10
     624:	r4 += -104
; if (unlikely(ret >= 1)) {
     625:	r1 = r9
     626:	r2 = 0 ll
     628:	r3 = 4294967295 ll
; entry->tx_closing = 0;
     630:	r5 = 20
     631:	call 25
     632:	r8 &= 255
; if (tcp) {
     633:	r1 = r8
     634:	r1 += -1
     635:	if r1 < 3 goto +151 <LBB5_105>
; entry->seen_non_syn |= !syn;
     636:	r4 = *(u64 *)(r10 - 264)
     637:	if r8 == 0 goto +1 <LBB5_95>
     638:	goto -162 <LBB5_67>

LBB5_95:
     639:	r1 = *(u64 *)(r10 - 248)
     640:	r2 = *(u8 *)(r1 + 6)
     641:	*(u64 *)(r10 - 224) = r2
     642:	r6 = *(u8 *)(r1 + 7)
     643:	r8 = r10
     644:	r8 += -104
     645:	r9 = *(u64 *)(r10 - 192)
     646:	r1 = r9
     647:	r2 = 0
; if (entry->seen_non_syn)
     648:	r3 = r8
     649:	r4 = 4
     650:	call 26
     651:	r1 = r9
; return ktime_get_ns();
     652:	r2 = 0
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     653:	r3 = r8
; entry->lifetime = now + lifetime;
     654:	r4 = 4
     655:	r5 = 2
     656:	call 9
; seen_flags |= *accumulated_flags;
     657:	r6 <<= 8
     658:	r1 = *(u64 *)(r10 - 224)
     659:	r6 |= r1
     660:	r1 = r9
     661:	call 34
     662:	r8 = r0
     663:	r1 = r9
; if (*last_report + CT_REPORT_INTERVAL < now ||
     664:	call 34
     665:	*(u32 *)(r10 - 100) = r0
     666:	r1 = 269489410
     667:	*(u32 *)(r10 - 104) = r1
     668:	*(u32 *)(r10 - 96) = r8
     669:	r8 <<= 32
     670:	r8 >>= 32
     671:	r1 = r8
     672:	r1 /= r6
; *accumulated_flags = seen_flags;
     673:	r1 *= r6
; *last_report = now;
     674:	r8 -= r1
     675:	r1 = 0
     676:	*(u32 *)(r10 - 88) = r1
     677:	r8 += 1
     678:	*(u32 *)(r10 - 92) = r8
     679:	r4 = r10
; switch(ret) {
     680:	r4 += -104
     681:	r1 = r9
; tuple->flags = flags;
     682:	r2 = 0 ll
     684:	r3 = 4294967295 ll
; if (IS_ERR(ret))
     686:	r5 = 20
     687:	call 25
     688:	r1 = 0
     689:	*(u64 *)(r10 - 72) = r1
     690:	*(u64 *)(r10 - 64) = r1
     691:	*(u64 *)(r10 - 56) = r1
     692:	*(u64 *)(r10 - 80) = r1
     693:	*(u64 *)(r10 - 88) = r1
     694:	*(u64 *)(r10 - 96) = r1
     695:	*(u64 *)(r10 - 104) = r1
; dst->p4 = src->p4;
     696:	r1 = *(u64 *)(r10 - 240)
; dst->p3 = src->p3;
     697:	*(u16 *)(r10 - 66) = r1
     698:	r6 = *(u64 *)(r10 - 264)
; dst->p2 = src->p2;
     699:	r6 <<= 3
; dst->p1 = src->p1;
     700:	*(u16 *)(r10 - 68) = r6
     701:	*(u64 *)(r10 - 224) = r8
; if (tuple->nexthdr == IPPROTO_TCP) {
     702:	*(u16 *)(r10 - 64) = r8
     703:	r1 = *(u8 *)(r10 - 108)
; union tcp_flags tcp_flags = { 0 };
     704:	if r1 != 6 goto +1 <LBB5_97>
     705:	*(u16 *)(r10 - 68) = r6

LBB5_97:
; tuple->flags = TUPLE_F_IN;
     706:	call 5
     707:	r0 /= 1000000000
; ret = ct_lookup6(get_ct_map6(tuple), tuple, skb, l4_off, CT_EGRESS,
     708:	r1 = r0
     709:	r1 += 60
     710:	*(u32 *)(r10 - 72) = r1
     711:	r1 = r0
     712:	r1 <<= 32
     713:	r1 >>= 32
     714:	r2 = *(u32 *)(r10 - 56)
; switch (tuple->nexthdr) {
     715:	r2 += 5
     716:	r2 <<= 32
     717:	r2 >>= 32
     718:	if r2 >= r1 goto +1 <LBB5_99>
     719:	*(u32 *)(r10 - 56) = r0

LBB5_99:
     720:	r1 = 1
     721:	*(u64 *)(r10 - 88) = r1
; __u8 type;
     722:	r9 = *(u64 *)(r10 - 192)
     723:	r1 = *(u32 *)(r9 + 0)
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     724:	*(u64 *)(r10 - 80) = r1
     725:	r1 = *(u32 *)(r9 + 60)
     726:	if r1 != 1 goto +1 <LBB5_101>
     727:	*(u16 *)(r10 - 68) = r6

LBB5_101:
     728:	r1 = r9
     729:	call 34
     730:	*(u32 *)(r10 - 36) = r0
     731:	r1 = 269495810
     732:	*(u32 *)(r10 - 40) = r1
; tuple->dport = 0;
     733:	*(u32 *)(r10 - 32) = r7
     734:	r6 = 0
; tuple->sport = 0;
     735:	*(u32 *)(r10 - 28) = r6
     736:	*(u32 *)(r10 - 24) = r6
; tuple->dport = 0;
     737:	r4 = r10
     738:	r4 += -40
     739:	r1 = r9
; switch (type) {
     740:	r2 = 0 ll
     742:	r3 = 4294967295 ll
     744:	r5 = 20
     745:	call 25
; tuple->dport = ICMPV6_ECHO_REQUEST;
     746:	*(u32 *)(r10 - 60) = r6
     747:	r2 = r10
     748:	r2 += -120
     749:	r3 = r10
     750:	r3 += -104
     751:	r7 = *(u64 *)(r10 - 216)
     752:	r1 = r7
     753:	r4 = 0
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     754:	call 2
     755:	r0 <<= 32
     756:	r0 s>>= 32
     757:	if r0 s> -1 goto +1 <LBB5_103>
     758:	goto +21 <LBB5_104>

LBB5_103:
     759:	r1 = *(u8 *)(r10 - 107)
     760:	r2 = *(u64 *)(r10 - 120)
     761:	*(u64 *)(r10 - 40) = r2
     762:	r2 = 1
     763:	*(u8 *)(r10 - 28) = r2
     764:	r1 |= 2
     765:	*(u8 *)(r10 - 27) = r1
     766:	r1 = *(u16 *)(r10 - 68)
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     767:	r1 |= 16
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     768:	*(u16 *)(r10 - 68) = r1
     769:	*(u32 *)(r10 - 32) = r6
     770:	r2 = r10
     771:	r2 += -40
     772:	r3 = r10
     773:	r3 += -104
     774:	r1 = r7
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     775:	r4 = 0
     776:	call 2
     777:	r0 <<= 32
     778:	r0 s>>= 32
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     779:	if r0 s> -1 goto +7 <LBB5_105>

LBB5_104:
     780:	r1 = *(u64 *)(r10 - 208)
     781:	*(u8 *)(r10 - 107) = r1
     782:	r7 = 4294967138 ll
     784:	r1 = 0
     785:	*(u64 *)(r10 - 288) = r1
; tuple->flags |= TUPLE_F_RELATED;
     786:	goto +315 <LBB5_135>

LBB5_105:
     787:	r7 = *(u64 *)(r10 - 224)
     788:	*(u16 *)(r10 - 130) = r7
     789:	r6 = *(u16 *)(r10 - 132)
; break;
     790:	r1 = r9
     791:	call 34
     792:	*(u32 *)(r10 - 100) = r0
     793:	r1 = 269491714
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
     794:	*(u32 *)(r10 - 104) = r1
     795:	r1 = r7
     796:	r1 &= 65535
     797:	*(u32 *)(r10 - 96) = r1
     798:	*(u32 *)(r10 - 92) = r6
     799:	r1 = 0
     800:	*(u32 *)(r10 - 88) = r1
     801:	r4 = r10
     802:	r4 += -104
; if (dir == CT_INGRESS)
     803:	r1 = r9
     804:	r2 = 0 ll
; if (ct_entry_alive(entry))
     806:	r3 = 4294967295 ll
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     808:	r5 = 20
; entry->lifetime = now + lifetime;
     809:	call 25
     810:	r2 = r10
     811:	r2 += -136
; seen_flags |= *accumulated_flags;
     812:	r1 = 0 ll
     814:	call 1
     815:	r1 = r9
     816:	r9 = r0
     817:	if r9 == 0 goto +232 <LBB5_128>
; if (*last_report + CT_REPORT_INTERVAL < now ||
     818:	r8 = *(u8 *)(r9 + 5)
     819:	r8 <<= 8
     820:	r2 = *(u8 *)(r9 + 4)
     821:	r8 |= r2
     822:	r2 = *(u8 *)(r9 + 2)
     823:	*(u64 *)(r10 - 216) = r2
     824:	r7 = *(u8 *)(r9 + 3)
     825:	r2 = *(u8 *)(r9 + 0)
     826:	*(u64 *)(r10 - 240) = r2
; *accumulated_flags = seen_flags;
     827:	r6 = *(u8 *)(r9 + 1)
; *last_report = now;
     828:	call 34
     829:	*(u32 *)(r10 - 100) = r0
     830:	r1 = 269491970
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
     831:	*(u32 *)(r10 - 104) = r1
     832:	*(u32 *)(r10 - 92) = r8
     833:	r1 = 0
     834:	*(u32 *)(r10 - 88) = r1
     835:	r6 <<= 8
; uint32_t hash = get_hash_recalc(skb);
     836:	r1 = *(u64 *)(r10 - 240)
     837:	r6 |= r1
; struct debug_msg msg = {
     838:	r7 <<= 8
     839:	r1 = *(u64 *)(r10 - 216)
     840:	r7 |= r1
     841:	r7 <<= 16
     842:	r7 |= r6
     843:	*(u32 *)(r10 - 96) = r7
     844:	r4 = r10
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
     845:	r4 += -104
; struct debug_msg msg = {
     846:	r1 = *(u64 *)(r10 - 192)
     847:	r2 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     849:	r3 = 4294967295 ll
     851:	r5 = 20
     852:	call 25

LBB5_107:
     853:	r1 = *(u64 *)(r10 - 208)
     854:	*(u8 *)(r10 - 107) = r1
     855:	r1 = *(u8 *)(r9 + 1)
     856:	r1 <<= 8
; switch(ret) {
     857:	r2 = *(u8 *)(r9 + 0)
     858:	r1 |= r2
     859:	r8 = *(u8 *)(r9 + 3)
     860:	r8 <<= 8
     861:	r2 = *(u8 *)(r9 + 2)
     862:	r8 |= r2
     863:	r8 <<= 16
     864:	r8 |= r1
     865:	r5 = *(u8 *)(r9 + 9)
     866:	r5 <<= 8
     867:	r1 = *(u8 *)(r9 + 8)
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     868:	*(u32 *)(r10 - 40) = r8
     869:	r3 = *(u8 *)(r9 + 1)
     870:	r3 <<= 8
     871:	r2 = *(u8 *)(r9 + 0)
     872:	r3 |= r2
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     873:	r4 = *(u8 *)(r9 + 2)
     874:	r2 = *(u8 *)(r9 + 3)
; struct lb6_service *svc;
     875:	r2 <<= 8
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     876:	r2 |= r4
     877:	r2 <<= 16
     878:	r2 |= r3
     879:	r6 = *(u32 *)(r10 - 184)
     880:	if r6 != r2 goto +6 <LBB5_109>
; skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
     881:	r2 = 1
     882:	*(u64 *)(r10 - 272) = r2
     883:	r8 = 536868106
     884:	*(u32 *)(r10 - 8) = r8
     885:	r3 = r6
     886:	goto +9 <LBB5_111>

LBB5_109:
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     887:	r3 = 1
     888:	*(u64 *)(r10 - 272) = r3
; return get_hash_recalc(skb);
     889:	r3 = 0
     890:	r4 = *(u64 *)(r10 - 264)
     891:	if r4 != 0 goto +4 <LBB5_111>
; if (weight) {
     892:	*(u32 *)(r10 - 120) = r2
     893:	r3 = 0
; struct lb6_key *key,
     894:	r2 = 0
; seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
     895:	*(u64 *)(r10 - 272) = r2

LBB5_111:
     896:	*(u64 *)(r10 - 288) = r3
     897:	r5 |= r1
; if (seq && seq->count != 0)
     898:	*(u64 *)(r10 - 240) = r5
     899:	r1 = *(u8 *)(r10 - 108)
     900:	*(u64 *)(r10 - 208) = r1
; slave = lb_next_rr(skb, seq, hash);
     901:	r3 = r10
     902:	r3 += -40
; __u8 offset = hash % seq->count;
     903:	r1 = *(u64 *)(r10 - 192)
     904:	r2 = 30
     905:	r4 = 4
     906:	r5 = 0
     907:	call 9
; if (offset < LB_RR_MAX_SEQ) {
     908:	r7 = 4294967155 ll
; slave = seq->idx[offset] + 1;
     910:	r0 <<= 32
     911:	r0 s>>= 32
     912:	if r0 s< 0 goto -428 <LBB5_69>
; uint32_t hash = get_hash_recalc(skb);
     913:	*(u64 *)(r10 - 216) = r6
     914:	r1 = r10
; struct debug_msg msg = {
     915:	r1 += -136
     916:	r3 = r10
     917:	r3 += -40
     918:	r2 = 4
     919:	r4 = 4
     920:	r5 = 0
     921:	call 28
     922:	r6 = *(u32 *)(r10 - 8)
     923:	if r6 == 0 goto +41 <LBB5_115>
     924:	*(u64 *)(r10 - 264) = r0
     925:	*(u64 *)(r10 - 248) = r8
; uint32_t hash = get_hash_recalc(skb);
     926:	r8 = *(u64 *)(r10 - 192)
     927:	r1 = r8
; struct debug_msg msg = {
     928:	call 34
     929:	*(u32 *)(r10 - 100) = r0
     930:	r1 = 269492738
     931:	*(u32 *)(r10 - 104) = r1
     932:	r1 = *(u64 *)(r10 - 216)
     933:	*(u32 *)(r10 - 96) = r1
; slave = (hash % count) + 1;
     934:	*(u32 *)(r10 - 92) = r6
     935:	r1 = 0
     936:	*(u32 *)(r10 - 88) = r1
     937:	r4 = r10
     938:	r4 += -104
     939:	r1 = r8
     940:	r2 = 0 ll
; struct debug_msg msg = {
     942:	r3 = 4294967295 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     944:	r5 = 20
     945:	call 25
     946:	r3 = r10
     947:	r3 += -8
     948:	r1 = r8
     949:	r8 = *(u64 *)(r10 - 248)
     950:	r2 = 26
     951:	r4 = 4
     952:	r5 = 0
     953:	call 9
; struct ct_entry entry = { };
     954:	r0 <<= 32
     955:	r0 s>>= 32
     956:	if r0 s< 0 goto -472 <LBB5_69>
     957:	r1 = r10
     958:	r1 += -184
     959:	r3 = r10
     960:	r3 += -8
; bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
     961:	r2 = 4
     962:	r4 = 4
; entry.rev_nat_index = ct_state->rev_nat_index;
     963:	r5 = *(u64 *)(r10 - 264)
     964:	call 28

LBB5_115:
; entry.slave = ct_state->slave;
     965:	r1 = *(u64 *)(r10 - 192)
; entry.lb_loopback = ct_state->loopback;
     966:	r2 = 24
     967:	r3 = 0
     968:	r6 = r0
; if (tcp) {
     969:	r4 = r0
; entry->seen_non_syn |= !syn;
     970:	r5 = 0
     971:	call 10
; return ktime_get_ns();
     972:	r7 = 4294967143 ll
; entry->lifetime = now + lifetime;
     974:	r0 <<= 32
     975:	r0 s>>= 32
     976:	r5 = *(u64 *)(r10 - 200)
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     977:	if r0 s< 0 goto -493 <LBB5_69>
     978:	r1 = *(u64 *)(r10 - 256)
     979:	if r1 == 0 goto +17 <LBB5_118>
; if (*last_report + CT_REPORT_INTERVAL < now ||
     980:	r2 = *(u64 *)(r10 - 256)
     981:	r2 &= 65535
     982:	r2 += r5
     983:	r7 = r5
     984:	r5 = *(u64 *)(r10 - 232)
; *last_report = now;
     985:	r5 |= 16
     986:	r5 &= 65535
; entry.tx_packets = 1;
     987:	r1 = *(u64 *)(r10 - 192)
; entry.tx_bytes = skb->len;
     988:	r3 = 0
     989:	r4 = r6
; uint32_t hash = get_hash_recalc(skb);
     990:	call 11
     991:	r5 = r7
; struct debug_msg msg = {
     992:	r7 = 4294967142 ll
     994:	r0 <<= 32
     995:	r0 s>>= 32
     996:	if r0 s< 0 goto -512 <LBB5_69>

LBB5_118:
     997:	r1 = *(u8 *)(r9 + 4)
     998:	r4 = *(u8 *)(r9 + 5)
     999:	r4 <<= 8
; entry.tx_packets = 1;
    1000:	r4 |= r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1001:	if r4 == 0 goto +46 <LBB5_127>
    1002:	r3 = *(u16 *)(r10 - 132)
    1003:	if r3 == r4 goto +44 <LBB5_127>
    1004:	r1 = *(u64 *)(r10 - 208)
    1005:	if r1 == 17 goto +2 <LBB5_122>
    1006:	r1 = *(u64 *)(r10 - 208)
    1007:	if r1 != 6 goto +40 <LBB5_127>

LBB5_122:
; entry.src_sec_id = ct_state->src_sec_id;
    1008:	r9 = r8
    1009:	r2 = *(u64 *)(r10 - 256)
; entry.tx_packets = 1;
    1010:	r2 &= 65535
    1011:	r2 += r5
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    1012:	*(u16 *)(r10 - 104) = r4
    1013:	r1 = r5
    1014:	r5 = *(u64 *)(r10 - 232)
    1015:	r5 |= 2
    1016:	r5 &= 65535
    1017:	r8 = r1
    1018:	r6 = *(u64 *)(r10 - 192)
    1019:	r1 = r6
    1020:	call 11
; tuple->sport = type;
    1021:	r7 = 4294967142 ll
    1023:	r0 <<= 32
    1024:	r0 s>>= 32
    1025:	if r0 s< 0 goto +12 <LBB5_124>
    1026:	r2 = r8
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
    1027:	r2 += 2
    1028:	r3 = r10
    1029:	r3 += -104
    1030:	r1 = r6
    1031:	r4 = 2
    1032:	r5 = 0
    1033:	call 9
    1034:	r7 = r0
    1035:	r7 <<= 32
    1036:	r7 s>>= 63
    1037:	r7 &= -141

LBB5_124:
    1038:	r1 = r7
    1039:	r1 <<= 32
    1040:	r1 >>= 32
    1041:	r2 = 1
    1042:	if r1 == 2 goto +1 <LBB5_126>
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1043:	r2 = 0

LBB5_126:
    1044:	r1 >>= 31
    1045:	r1 |= r2
    1046:	r8 = r9
    1047:	if r1 != 0 goto -563 <LBB5_69>

LBB5_127:
    1048:	r7 = 0
    1049:	goto -565 <LBB5_69>

LBB5_128:
    1050:	r1 = *(u16 *)(r10 - 132)
    1051:	if r1 == 0 goto +14 <LBB5_132>
    1052:	r2 = r10
    1053:	r2 += -136
    1054:	r1 = 0 ll
    1056:	call 1
    1057:	r9 = r0
    1058:	if r9 == 0 goto +5 <LBB5_131>
    1059:	r1 = *(u8 *)(r9 + 6)
    1060:	r8 = *(u8 *)(r9 + 7)
    1061:	r8 <<= 8
    1062:	r8 |= r1
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1063:	if r8 != 0 goto +41 <LBB5_136>

LBB5_131:
    1064:	r1 = 0
    1065:	*(u16 *)(r10 - 132) = r1

LBB5_132:
    1066:	r2 = r10
    1067:	r2 += -136
    1068:	r1 = 0 ll
    1070:	call 1
    1071:	r9 = r0
    1072:	if r9 == 0 goto +5 <LBB5_134>
    1073:	r1 = *(u8 *)(r9 + 6)
    1074:	r8 = *(u8 *)(r9 + 7)
; uint32_t hash = get_hash_recalc(skb);
    1075:	r8 <<= 8
    1076:	r8 |= r1
; struct debug_msg msg = {
    1077:	if r8 != 0 goto +27 <LBB5_136>

LBB5_134:
    1078:	r6 = *(u64 *)(r10 - 192)
    1079:	r1 = r6
    1080:	call 34
    1081:	*(u32 *)(r10 - 100) = r0
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1082:	r1 = 269491458
    1083:	*(u32 *)(r10 - 104) = r1
    1084:	r2 = 0
    1085:	*(u64 *)(r10 - 96) = r2
    1086:	r1 = 0
    1087:	*(u64 *)(r10 - 288) = r1
    1088:	*(u32 *)(r10 - 88) = r2
    1089:	r4 = r10
    1090:	r4 += -104
    1091:	r1 = r6
; struct debug_msg msg = {
    1092:	r2 = 0 ll
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1094:	r3 = 4294967295 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1096:	r5 = 20
    1097:	call 25
    1098:	r1 = *(u64 *)(r10 - 208)
    1099:	*(u8 *)(r10 - 107) = r1
    1100:	r7 = 4294967138 ll

LBB5_135:
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1102:	r1 = *(u64 *)(r10 - 264)
    1103:	*(u64 *)(r10 - 272) = r1
    1104:	goto -621 <LBB5_68>

LBB5_136:
    1105:	r7 = r10
; uint32_t hash = get_hash_recalc(skb);
    1106:	r7 += -104
    1107:	r6 = *(u64 *)(r10 - 192)
; struct debug_msg msg = {
    1108:	r1 = r6
    1109:	r2 = 0
    1110:	r3 = r7
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1111:	r4 = 4
    1112:	call 26
    1113:	r1 = r6
; struct debug_msg msg = {
    1114:	r2 = 0
    1115:	r3 = r7
    1116:	r4 = 4
    1117:	r5 = 2
    1118:	call 9
    1119:	r1 = r6
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1120:	call 34
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1121:	r7 = r0
    1122:	r1 = r6
    1123:	call 34
    1124:	*(u32 *)(r10 - 100) = r0
    1125:	r1 = 269489410
    1126:	*(u32 *)(r10 - 104) = r1
    1127:	r1 = 0
    1128:	*(u32 *)(r10 - 88) = r1
    1129:	*(u32 *)(r10 - 96) = r7
    1130:	r7 <<= 32
; if ((entry = map_lookup_elem(map, tuple))) {
    1131:	r7 >>= 32
    1132:	r1 = r7
    1133:	r1 /= r8
    1134:	r1 *= r8
    1135:	r7 -= r1
    1136:	r7 += 1
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1137:	*(u64 *)(r10 - 224) = r7
    1138:	*(u32 *)(r10 - 92) = r7
    1139:	r4 = r10
; uint32_t hash = get_hash_recalc(skb);
    1140:	r4 += -104
    1141:	r1 = r6
; struct debug_msg msg = {
    1142:	r2 = 0 ll
    1144:	r3 = 4294967295 ll
    1146:	r5 = 20
    1147:	call 25
    1148:	r2 = r10
    1149:	r2 += -120
    1150:	r1 = *(u64 *)(r10 - 216)
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1151:	call 1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1152:	if r0 == 0 goto -300 <LBB5_107>
    1153:	r1 = *(u64 *)(r10 - 224)
    1154:	*(u16 *)(r0 + 40) = r1
    1155:	goto -303 <LBB5_107>

LBB5_138:
    1156:	r1 = 8
    1157:	*(u16 *)(r10 - 112) = r1

LBB5_139:
    1158:	r1 = 0
; return !entry->rx_closing || !entry->tx_closing;
    1159:	*(u64 *)(r10 - 280) = r1
    1160:	goto +13 <LBB5_141>

LBB5_140:
    1161:	r3 = r10
    1162:	r3 += -112
; if (ct_entry_alive(entry)) {
    1163:	r1 = r9
    1164:	r2 = r6
; if (tcp) {
    1165:	r4 = 4
    1166:	call 26
; entry->seen_non_syn |= !syn;
    1167:	r1 = 1
    1168:	*(u64 *)(r10 - 280) = r1
    1169:	r7 = 4294967161 ll
    1171:	r0 <<= 32
    1172:	r0 s>>= 32
    1173:	if r0 s< 0 goto +212 <LBB5_161>

LBB5_141:
    1174:	*(u64 *)(r10 - 248) = r8
    1175:	r6 = *(u16 *)(r10 - 112)
    1176:	r7 = *(u16 *)(r10 - 110)
    1177:	r8 = *(u32 *)(r10 - 120)
    1178:	r9 = *(u32 *)(r10 - 116)
; if (entry->seen_non_syn)
    1179:	r1 = *(u64 *)(r10 - 192)
    1180:	call 34
    1181:	*(u32 *)(r10 - 100) = r0
    1182:	r1 = 269495298
; return ktime_get_ns();
    1183:	*(u32 *)(r10 - 104) = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1184:	*(u32 *)(r10 - 96) = r9
; entry->lifetime = now + lifetime;
    1185:	r9 = *(u64 *)(r10 - 192)
    1186:	*(u32 *)(r10 - 92) = r8
; seen_flags |= *accumulated_flags;
    1187:	r7 = be32 r7
    1188:	r1 = 4294901760 ll
    1190:	r7 &= r1
    1191:	r6 = be16 r6
    1192:	r7 |= r6
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1193:	*(u32 *)(r10 - 88) = r7
    1194:	r4 = r10
    1195:	r4 += -104
    1196:	r1 = r9
    1197:	r2 = 0 ll
    1199:	r3 = 4294967295 ll
    1201:	r5 = 20
; *accumulated_flags = seen_flags;
    1202:	call 25
; *last_report = now;
    1203:	r6 = *(u8 *)(r10 - 107)
    1204:	r7 = *(u8 *)(r10 - 108)
; ct_state->rev_nat_index = entry->rev_nat_index;
    1205:	r1 = r9
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1206:	call 34
    1207:	*(u32 *)(r10 - 100) = r0
    1208:	r1 = 269495554
    1209:	*(u32 *)(r10 - 104) = r1
    1210:	r7 <<= 8
    1211:	r7 |= r6
    1212:	*(u32 *)(r10 - 96) = r7
; skb->cb[CB_NAT46_STATE] = NAT46;
    1213:	r1 = 0
    1214:	*(u32 *)(r10 - 92) = r1
    1215:	*(u32 *)(r10 - 88) = r1
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1216:	r4 = r10
    1217:	r4 += -104
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1218:	r1 = r9
    1219:	r2 = 0 ll
    1221:	r3 = 4294967295 ll
; switch (action) {
    1223:	r5 = 20
    1224:	call 25
    1225:	r6 = *(u8 *)(r10 - 39)
    1226:	r1 = *(u8 *)(r10 - 40)
; ret = entry->rx_closing + entry->tx_closing;
    1227:	*(u64 *)(r10 - 296) = r1
    1228:	r2 = r10
    1229:	r2 += -120
    1230:	r8 = *(u64 *)(r10 - 208)
    1231:	r1 = r8
    1232:	call 1
; if (unlikely(ret >= 1)) {
    1233:	r7 = r0
    1234:	if r7 == 0 goto +153 <LBB5_162>
; entry->tx_closing = 0;
    1235:	*(u64 *)(r10 - 304) = r6
    1236:	r6 = *(u16 *)(r7 + 38)
    1237:	r8 = *(u32 *)(r7 + 32)
    1238:	r1 = r9
; if (tcp) {
    1239:	call 34
    1240:	*(u32 *)(r10 - 100) = r0
    1241:	r1 = 269486082
; entry->seen_non_syn |= !syn;
    1242:	*(u32 *)(r10 - 104) = r1
    1243:	*(u32 *)(r10 - 96) = r8
    1244:	r8 = 0
    1245:	*(u32 *)(r10 - 92) = r6
    1246:	*(u32 *)(r10 - 88) = r8
    1247:	r4 = r10
    1248:	r4 += -104
    1249:	r1 = r9
    1250:	r2 = 0 ll
    1252:	r3 = 4294967295 ll
; if (entry->seen_non_syn)
    1254:	r5 = 20
    1255:	call 25
    1256:	r1 = *(u16 *)(r7 + 36)
; return ktime_get_ns();
    1257:	r2 = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1258:	r2 &= 3
; entry->lifetime = now + lifetime;
    1259:	if r2 == 3 goto +41 <LBB5_149>
    1260:	r6 = 60
; seen_flags |= *accumulated_flags;
    1261:	r2 = *(u64 *)(r10 - 264)
    1262:	if r2 != 6 goto +16 <LBB5_146>
    1263:	r2 = *(u64 *)(r10 - 296)
    1264:	r2 ^= 1
    1265:	r2 &= 255
    1266:	r3 = r1
    1267:	r3 >>= 4
    1268:	r3 |= r2
    1269:	r2 = r3
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1270:	r2 <<= 4
    1271:	r2 &= 16
    1272:	r1 &= 65519
    1273:	r2 |= r1
    1274:	*(u16 *)(r7 + 36) = r2
    1275:	r3 &= 1
    1276:	r6 = 60
    1277:	if r3 == 0 goto +1 <LBB5_146>
    1278:	r6 = 21600

LBB5_146:
    1279:	call 5
; *accumulated_flags = seen_flags;
    1280:	r0 /= 1000000000
; *last_report = now;
    1281:	r6 += r0
    1282:	*(u32 *)(r7 + 32) = r6
    1283:	r2 = *(u8 *)(r7 + 42)
; tmp = tuple->sport;
    1284:	r1 = r2
; tuple->sport = tuple->dport;
    1285:	r3 = *(u64 *)(r10 - 304)
    1286:	r1 |= r3
; tmp = tuple->sport;
    1287:	r3 = r1
; tuple->sport = tuple->dport;
    1288:	r3 &= 255
    1289:	if r2 != r3 goto +8 <LBB5_148>
; dst->p1 = src->p1;
    1290:	r2 = *(u32 *)(r7 + 48)
    1291:	r2 += 5
    1292:	r3 = r0
; dst->p2 = src->p2;
    1293:	r3 <<= 32
    1294:	r3 >>= 32
    1295:	r2 <<= 32
    1296:	r2 >>= 32
; dst->p3 = src->p3;
    1297:	if r2 >= r3 goto +3 <LBB5_149>

LBB5_148:
    1298:	*(u8 *)(r7 + 42) = r1
    1299:	*(u32 *)(r7 + 48) = r0
    1300:	r8 = 128

LBB5_149:
; dst->p4 = src->p4;
    1301:	r1 = *(u16 *)(r7 + 38)
    1302:	*(u16 *)(r10 - 160) = r1
    1303:	r1 = *(u16 *)(r10 - 158)
    1304:	r1 &= 65534
; dst->p1 = src->p1;
    1305:	r2 = *(u16 *)(r7 + 36)
; tuple->dport = tmp;
    1306:	r3 = r2
    1307:	r3 >>= 3
; if (tuple->flags & TUPLE_F_IN)
    1308:	r3 &= 1
; tuple->flags |= TUPLE_F_IN;
    1309:	r1 |= r3
    1310:	*(u16 *)(r10 - 158) = r1
; if (tuple->flags & TUPLE_F_IN)
    1311:	r1 = *(u16 *)(r7 + 40)
    1312:	*(u16 *)(r10 - 140) = r1
    1313:	r2 &= 4
    1314:	if r2 == 0 goto +4 <LBB5_152>
    1315:	r1 = *(u32 *)(r9 + 60)
    1316:	if r1 != 0 goto +2 <LBB5_152>
    1317:	r1 = 2
    1318:	*(u32 *)(r9 + 60) = r1

LBB5_152:
    1319:	r1 = 1
; if ((entry = map_lookup_elem(map, tuple))) {
    1320:	lock *(u64 *)(r7 + 16) += r1
    1321:	r1 = *(u32 *)(r9 + 0)
    1322:	lock *(u64 *)(r7 + 24) += r1
    1323:	r1 = *(u64 *)(r10 - 280)
    1324:	if r1 == 2 goto +246 <LBB5_186>
    1325:	*(u64 *)(r10 - 208) = r8
    1326:	r1 <<= 32
    1327:	r1 >>= 32
    1328:	if r1 != 1 goto +271 <LBB5_190>
    1329:	r1 = *(u16 *)(r7 + 36)
    1330:	r2 = r1
    1331:	r2 &= 1
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1332:	r3 = r1
    1333:	r3 >>= 1
    1334:	r3 &= 1
; uint32_t hash = get_hash_recalc(skb);
    1335:	r3 = -r3
    1336:	if r2 == r3 goto +263 <LBB5_190>
; struct debug_msg msg = {
    1337:	r2 = r1
    1338:	r2 &= 65532
    1339:	*(u16 *)(r7 + 36) = r2
    1340:	r6 = 60
    1341:	r2 = *(u64 *)(r10 - 264)
    1342:	if r2 != 6 goto +16 <LBB5_158>
    1343:	r3 = *(u64 *)(r10 - 296)
    1344:	r3 ^= 1
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1345:	r3 &= 255
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1346:	r2 = r1
    1347:	r2 >>= 4
    1348:	r2 |= r3
    1349:	r3 = r2
    1350:	r3 <<= 4
    1351:	r3 &= 16
    1352:	r1 &= 65516
; return !entry->rx_closing || !entry->tx_closing;
    1353:	r3 |= r1
    1354:	*(u16 *)(r7 + 36) = r3
    1355:	r2 &= 1
    1356:	r6 = 60
; if (ct_entry_alive(entry)) {
    1357:	if r2 == 0 goto +1 <LBB5_158>
    1358:	r6 = 21600

LBB5_158:
; if (tcp) {
    1359:	call 5
    1360:	r0 /= 1000000000
; entry->seen_non_syn |= !syn;
    1361:	r6 += r0
    1362:	*(u32 *)(r7 + 32) = r6
    1363:	r2 = *(u8 *)(r7 + 42)
    1364:	r1 = r2
    1365:	r3 = *(u64 *)(r10 - 304)
    1366:	r1 |= r3
    1367:	r3 = r1
    1368:	r3 &= 255
    1369:	r9 = *(u64 *)(r10 - 192)
    1370:	if r2 != r3 goto +10 <LBB5_160>
    1371:	r2 = 0
    1372:	*(u64 *)(r10 - 208) = r2
; if (entry->seen_non_syn)
    1373:	r2 = *(u32 *)(r7 + 48)
    1374:	r2 += 5
    1375:	r3 = r0
    1376:	r3 <<= 32
; return ktime_get_ns();
    1377:	r3 >>= 32
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1378:	r2 <<= 32
; entry->lifetime = now + lifetime;
    1379:	r2 >>= 32
    1380:	if r2 >= r3 goto +219 <LBB5_190>

LBB5_160:
; seen_flags |= *accumulated_flags;
    1381:	*(u8 *)(r7 + 42) = r1
    1382:	*(u32 *)(r7 + 48) = r0
    1383:	r1 = 128
    1384:	*(u64 *)(r10 - 208) = r1
    1385:	goto +214 <LBB5_190>

LBB5_161:
    1386:	r4 = 0
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1387:	goto +2060 <LBB5_373>

LBB5_162:
    1388:	r2 = *(u8 *)(r10 - 107)
    1389:	r1 = r2
    1390:	r1 |= 1
    1391:	r3 = r2
    1392:	r3 &= 1
    1393:	if r3 == 0 goto +2 <LBB5_164>
    1394:	r2 &= 254
    1395:	r1 = r2

LBB5_164:
    1396:	r2 = *(u32 *)(r10 - 116)
; *accumulated_flags = seen_flags;
    1397:	r3 = *(u32 *)(r10 - 120)
; *last_report = now;
    1398:	*(u32 *)(r10 - 116) = r3
    1399:	*(u32 *)(r10 - 120) = r2
; ct_state->rev_nat_index = entry->rev_nat_index;
    1400:	r2 = *(u16 *)(r10 - 110)
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1401:	r3 = *(u16 *)(r10 - 112)
    1402:	*(u16 *)(r10 - 110) = r3
    1403:	*(u16 *)(r10 - 112) = r2
    1404:	*(u8 *)(r10 - 107) = r1
    1405:	r1 = *(u8 *)(r10 - 40)
    1406:	*(u64 *)(r10 - 296) = r1
    1407:	r6 = *(u8 *)(r10 - 39)
; skb->cb[CB_NAT46_STATE] = NAT46;
    1408:	r2 = r10
    1409:	r2 += -120
    1410:	r1 = r8
    1411:	call 1
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1412:	r7 = r0
    1413:	if r7 != 0 goto +4 <LBB5_167>
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1414:	r8 = 0

LBB5_166:
    1415:	r1 = 128
    1416:	*(u64 *)(r10 - 208) = r1
    1417:	goto +186 <LBB5_191>

LBB5_167:
    1418:	*(u64 *)(r10 - 304) = r6
    1419:	r6 = *(u16 *)(r7 + 38)
; switch (action) {
    1420:	r8 = *(u32 *)(r7 + 32)
    1421:	r1 = r9
    1422:	call 34
    1423:	*(u32 *)(r10 - 100) = r0
; ret = entry->rx_closing + entry->tx_closing;
    1424:	r1 = 269486082
    1425:	*(u32 *)(r10 - 104) = r1
    1426:	*(u32 *)(r10 - 96) = r8
    1427:	*(u32 *)(r10 - 92) = r6
    1428:	r1 = 0
    1429:	*(u32 *)(r10 - 88) = r1
; if (unlikely(ret >= 1)) {
    1430:	r4 = r10
    1431:	r4 += -104
; entry->tx_closing = 0;
    1432:	r1 = r9
    1433:	r2 = 0 ll
    1435:	r3 = 4294967295 ll
; if (tcp) {
    1437:	r5 = 20
    1438:	call 25
; entry->seen_non_syn |= !syn;
    1439:	r1 = *(u16 *)(r7 + 36)
    1440:	r2 = r1
    1441:	r2 &= 3
    1442:	r4 = 128
    1443:	if r2 == 3 goto +42 <LBB5_174>
    1444:	r6 = 60
    1445:	r2 = *(u64 *)(r10 - 264)
    1446:	r8 = *(u64 *)(r10 - 304)
    1447:	if r2 != 6 goto +16 <LBB5_171>
    1448:	r2 = *(u64 *)(r10 - 296)
    1449:	r2 ^= 1
; if (entry->seen_non_syn)
    1450:	r2 &= 255
    1451:	r3 = r1
    1452:	r3 >>= 4
    1453:	r3 |= r2
; return ktime_get_ns();
    1454:	r2 = r3
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1455:	r2 <<= 4
; entry->lifetime = now + lifetime;
    1456:	r2 &= 16
    1457:	r1 &= 65519
; seen_flags |= *accumulated_flags;
    1458:	r2 |= r1
    1459:	*(u16 *)(r7 + 36) = r2
    1460:	r3 &= 1
    1461:	r6 = 60
    1462:	if r3 == 0 goto +1 <LBB5_171>
    1463:	r6 = 21600

LBB5_171:
    1464:	call 5
    1465:	r0 /= 1000000000
    1466:	r6 += r0
    1467:	*(u32 *)(r7 + 32) = r6
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1468:	r2 = *(u8 *)(r7 + 42)
    1469:	r1 = r2
    1470:	r1 |= r8
    1471:	r3 = r1
    1472:	r3 &= 255
    1473:	if r2 != r3 goto +9 <LBB5_173>
    1474:	r4 = 0
    1475:	r2 = *(u32 *)(r7 + 48)
    1476:	r2 += 5
    1477:	r3 = r0
; *accumulated_flags = seen_flags;
    1478:	r3 <<= 32
; *last_report = now;
    1479:	r3 >>= 32
    1480:	r2 <<= 32
    1481:	r2 >>= 32
    1482:	if r2 >= r3 goto +3 <LBB5_174>

LBB5_173:
; if (dir == CT_INGRESS)
    1483:	*(u8 *)(r7 + 42) = r1
    1484:	*(u32 *)(r7 + 48) = r0
    1485:	r4 = 128

LBB5_174:
; return !entry->rx_closing || !entry->tx_closing;
    1486:	*(u64 *)(r10 - 208) = r4
; if (ct_entry_alive(entry))
    1487:	r1 = *(u16 *)(r7 + 38)
; return ktime_get_ns();
    1488:	*(u16 *)(r10 - 160) = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1489:	r1 = *(u16 *)(r10 - 158)
; entry->lifetime = now + lifetime;
    1490:	r1 &= 65534
    1491:	r2 = *(u16 *)(r7 + 36)
    1492:	r3 = r2
; seen_flags |= *accumulated_flags;
    1493:	r3 >>= 3
    1494:	r3 &= 1
    1495:	r1 |= r3
    1496:	*(u16 *)(r10 - 158) = r1
    1497:	r1 = *(u16 *)(r7 + 40)
    1498:	*(u16 *)(r10 - 140) = r1
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1499:	r2 &= 4
    1500:	if r2 == 0 goto +4 <LBB5_177>
    1501:	r1 = *(u32 *)(r9 + 60)
    1502:	if r1 != 0 goto +2 <LBB5_177>
    1503:	r1 = 2
    1504:	*(u32 *)(r9 + 60) = r1

LBB5_177:
    1505:	r8 = 1
    1506:	r1 = 1
    1507:	lock *(u64 *)(r7 + 16) += r1
; *accumulated_flags = seen_flags;
    1508:	r1 = *(u32 *)(r9 + 0)
; *last_report = now;
    1509:	lock *(u64 *)(r7 + 24) += r1
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1510:	r1 = *(u64 *)(r10 - 280)
    1511:	if r1 == 2 goto +922 <LBB5_264>
    1512:	r1 <<= 32
    1513:	r1 >>= 32
    1514:	if r1 != 1 goto +89 <LBB5_191>
    1515:	r1 = *(u16 *)(r7 + 36)
; if (dir == CT_INGRESS)
    1516:	r2 = r1
    1517:	r2 &= 1
    1518:	r3 = r1
; return !entry->rx_closing || !entry->tx_closing;
    1519:	r3 >>= 1
; if (ct_entry_alive(entry))
    1520:	r3 &= 1
; return ktime_get_ns();
    1521:	r3 = -r3
    1522:	if r2 == r3 goto +81 <LBB5_191>
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1523:	r2 = r1
; entry->lifetime = now + lifetime;
    1524:	r2 &= 65532
    1525:	*(u16 *)(r7 + 36) = r2
    1526:	r6 = 60
; seen_flags |= *accumulated_flags;
    1527:	r2 = *(u64 *)(r10 - 264)
    1528:	if r2 != 6 goto +16 <LBB5_183>
    1529:	r3 = *(u64 *)(r10 - 296)
    1530:	r3 ^= 1
    1531:	r3 &= 255
    1532:	r2 = r1
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1533:	r2 >>= 4
    1534:	r2 |= r3
    1535:	r3 = r2
    1536:	r3 <<= 4
    1537:	r3 &= 16
    1538:	r1 &= 65516
    1539:	r3 |= r1
    1540:	*(u16 *)(r7 + 36) = r3
    1541:	r2 &= 1
; *accumulated_flags = seen_flags;
    1542:	r6 = 60
; *last_report = now;
    1543:	if r2 == 0 goto +1 <LBB5_183>
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
    1544:	r6 = 21600

LBB5_183:
    1545:	call 5
    1546:	r0 /= 1000000000
; uint32_t hash = get_hash_recalc(skb);
    1547:	r6 += r0
    1548:	*(u32 *)(r7 + 32) = r6
; struct debug_msg msg = {
    1549:	r2 = *(u8 *)(r7 + 42)
    1550:	r1 = r2
    1551:	r3 = *(u64 *)(r10 - 304)
    1552:	r1 |= r3
    1553:	r3 = r1
    1554:	r3 &= 255
    1555:	r9 = *(u64 *)(r10 - 192)
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
    1556:	r8 = 1
    1557:	if r2 != r3 goto +10 <LBB5_185>
; struct debug_msg msg = {
    1558:	r2 = 0
    1559:	*(u64 *)(r10 - 208) = r2
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    1560:	r2 = *(u32 *)(r7 + 48)
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1561:	r2 += 5
    1562:	r3 = r0
    1563:	r3 <<= 32
    1564:	r3 >>= 32
    1565:	r2 <<= 32
    1566:	r2 >>= 32
    1567:	if r2 >= r3 goto +36 <LBB5_191>

LBB5_185:
    1568:	*(u8 *)(r7 + 42) = r1
; if (conn_is_dns(tuple->dport))
    1569:	*(u32 *)(r7 + 48) = r0
    1570:	goto -156 <LBB5_166>

LBB5_186:
    1571:	r1 = *(u16 *)(r7 + 36)
    1572:	r1 |= 2
    1573:	*(u16 *)(r7 + 36) = r1
    1574:	r2 = 128
    1575:	*(u64 *)(r10 - 208) = r2
    1576:	r1 &= 3
    1577:	if r1 != 3 goto +22 <LBB5_190>
    1578:	call 5
    1579:	r0 /= 1000000000
; void *data_end = (void *) (long) skb->data_end;
    1580:	r1 = r0
; void *data = (void *) (long) skb->data;
    1581:	r1 += 10
; if (data + ETH_HLEN + l3_len > data_end)
    1582:	*(u32 *)(r7 + 32) = r1
    1583:	r2 = *(u8 *)(r7 + 42)
    1584:	r1 = r2
    1585:	r3 = *(u64 *)(r10 - 304)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1586:	r1 |= r3
    1587:	r3 = r1
    1588:	r3 &= 255
    1589:	if r2 != r3 goto +8 <LBB5_189>
; addr->p4 &= GET_PREFIX(prefix);
    1590:	r2 = *(u32 *)(r7 + 48)
; addr->p3 &= GET_PREFIX(prefix);
    1591:	r2 += 5
    1592:	r3 = r0
    1593:	r3 <<= 32
    1594:	r3 >>= 32
    1595:	r2 <<= 32
    1596:	r2 >>= 32
; .ip6 = *addr,
    1597:	if r2 >= r3 goto +2 <LBB5_190>

LBB5_189:
    1598:	*(u8 *)(r7 + 42) = r1
    1599:	*(u32 *)(r7 + 48) = r0

LBB5_190:
    1600:	r8 = *(u8 *)(r10 - 107)
    1601:	r8 >>= 1
    1602:	r8 &= 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1603:	r8 |= 2

LBB5_191:
; return map_lookup_elem(map, &key);
    1604:	r6 = *(u16 *)(r10 - 160)
    1605:	r1 = r9
    1606:	call 34
    1607:	*(u32 *)(r10 - 100) = r0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1608:	r1 = 269487874
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1609:	*(u32 *)(r10 - 104) = r1
    1610:	*(u32 *)(r10 - 96) = r8
    1611:	*(u32 *)(r10 - 92) = r6
; .ip6 = *addr,
    1612:	r6 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1613:	*(u32 *)(r10 - 88) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1614:	r4 = r10
    1615:	r4 += -104
    1616:	r1 = r9
    1617:	r2 = 0 ll
    1619:	r3 = 4294967295 ll
; return map_lookup_elem(map, &key);
    1621:	r5 = 20
    1622:	call 25
    1623:	r2 = 1500
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1624:	r1 = *(u16 *)(r10 - 112)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1625:	if r1 == 13568 goto +1 <LBB5_193>
    1626:	r2 = *(u64 *)(r10 - 208)

LBB5_193:
    1627:	*(u64 *)(r10 - 304) = r2
; .ip6 = *addr,
    1628:	*(u64 *)(r10 - 264) = r8
    1629:	r1 = 72057594037927986 ll
; addr->p3 &= GET_PREFIX(prefix);
    1631:	*(u64 *)(r10 - 104) = r1
    1632:	*(u32 *)(r10 - 92) = r6
    1633:	*(u64 *)(r10 - 88) = r6
    1634:	r8 = *(u64 *)(r10 - 216)
    1635:	r1 = r8
    1636:	r1 &= 12648447
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1637:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1638:	r2 = r10
    1639:	r2 += -104
    1640:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1642:	call 1
    1643:	if r0 == 0 goto +1 <LBB5_194>
    1644:	goto +250 <LBB5_211>

LBB5_194:
; .ip6 = *addr,
    1645:	r1 = 72057594037927985 ll
; addr->p3 &= GET_PREFIX(prefix);
    1647:	*(u64 *)(r10 - 104) = r1
    1648:	r6 = 0
    1649:	*(u32 *)(r10 - 92) = r6
    1650:	*(u64 *)(r10 - 88) = r6
    1651:	r1 = r8
    1652:	r1 &= 8454143
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1653:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1654:	r2 = r10
    1655:	r2 += -104
    1656:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1658:	call 1
    1659:	if r0 != 0 goto +235 <LBB5_211>
    1660:	r1 = 72057594037927984 ll
; .ip6 = *addr,
    1662:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1663:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1664:	*(u64 *)(r10 - 88) = r6
    1665:	r1 = r8
    1666:	r1 &= 65535
    1667:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1668:	r2 = r10
; return map_lookup_elem(map, &key);
    1669:	r2 += -104
    1670:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1672:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1673:	if r0 != 0 goto +221 <LBB5_211>
    1674:	r1 = 72057594037927983 ll
; .ip6 = *addr,
    1676:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1677:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1678:	*(u32 *)(r10 - 92) = r6
    1679:	*(u64 *)(r10 - 88) = r6
    1680:	r1 = r8
    1681:	r1 &= 65279
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1682:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1683:	r2 = r10
    1684:	r2 += -104
    1685:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1687:	call 1
    1688:	if r0 != 0 goto +206 <LBB5_211>
    1689:	r1 = 72057594037927982 ll
; .ip6 = *addr,
    1691:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1692:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1693:	*(u64 *)(r10 - 88) = r6
    1694:	r1 = r8
    1695:	r1 &= 64767
    1696:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1697:	r2 = r10
; return map_lookup_elem(map, &key);
    1698:	r2 += -104
    1699:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1701:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1702:	if r0 != 0 goto +192 <LBB5_211>
    1703:	r1 = 72057594037927981 ll
; .ip6 = *addr,
    1705:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1706:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1707:	*(u32 *)(r10 - 92) = r6
    1708:	*(u64 *)(r10 - 88) = r6
    1709:	r1 = r8
    1710:	r1 &= 63743
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1711:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1712:	r2 = r10
    1713:	r2 += -104
    1714:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1716:	call 1
    1717:	if r0 != 0 goto +177 <LBB5_211>
    1718:	r1 = 72057594037927980 ll
; .ip6 = *addr,
    1720:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1721:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1722:	*(u64 *)(r10 - 88) = r6
    1723:	r1 = r8
    1724:	r1 &= 61695
    1725:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1726:	r2 = r10
; return map_lookup_elem(map, &key);
    1727:	r2 += -104
    1728:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1730:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1731:	if r0 != 0 goto +163 <LBB5_211>
    1732:	r1 = 72057594037927979 ll
; .ip6 = *addr,
    1734:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1735:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1736:	*(u32 *)(r10 - 92) = r6
    1737:	*(u64 *)(r10 - 88) = r6
    1738:	r1 = r8
    1739:	r1 &= 57599
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1740:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1741:	r2 = r10
    1742:	r2 += -104
    1743:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1745:	call 1
    1746:	if r0 != 0 goto +148 <LBB5_211>
    1747:	r1 = 72057594037927978 ll
; .ip6 = *addr,
    1749:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1750:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1751:	*(u64 *)(r10 - 88) = r6
    1752:	r1 = r8
    1753:	r1 &= 49407
    1754:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1755:	r2 = r10
; return map_lookup_elem(map, &key);
    1756:	r2 += -104
    1757:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1759:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1760:	if r0 != 0 goto +134 <LBB5_211>
    1761:	r1 = 72057594037927977 ll
; .ip6 = *addr,
    1763:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1764:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1765:	*(u32 *)(r10 - 92) = r6
    1766:	*(u64 *)(r10 - 88) = r6
    1767:	r1 = r8
    1768:	r1 &= 33023
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1769:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1770:	r2 = r10
    1771:	r2 += -104
    1772:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1774:	call 1
    1775:	if r0 != 0 goto +119 <LBB5_211>
    1776:	r1 = 72057594037927976 ll
; .ip6 = *addr,
    1778:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1779:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1780:	*(u64 *)(r10 - 88) = r6
    1781:	r1 = r8
    1782:	r1 &= 255
    1783:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1784:	r2 = r10
; return map_lookup_elem(map, &key);
    1785:	r2 += -104
    1786:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1788:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1789:	if r0 != 0 goto +105 <LBB5_211>
    1790:	r1 = 72057594037927975 ll
; .ip6 = *addr,
    1792:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1793:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1794:	*(u32 *)(r10 - 92) = r6
    1795:	*(u64 *)(r10 - 88) = r6
    1796:	r1 = r8
    1797:	r1 &= 254
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1798:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1799:	r2 = r10
    1800:	r2 += -104
    1801:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1803:	call 1
    1804:	if r0 != 0 goto +90 <LBB5_211>
    1805:	r1 = 72057594037927974 ll
; .ip6 = *addr,
    1807:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1808:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1809:	*(u64 *)(r10 - 88) = r6
    1810:	r1 = r8
    1811:	r1 &= 252
    1812:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1813:	r2 = r10
; return map_lookup_elem(map, &key);
    1814:	r2 += -104
    1815:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1817:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1818:	if r0 != 0 goto +76 <LBB5_211>
    1819:	r1 = 72057594037927973 ll
; .ip6 = *addr,
    1821:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1822:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1823:	*(u32 *)(r10 - 92) = r6
    1824:	*(u64 *)(r10 - 88) = r6
    1825:	r1 = r8
    1826:	r1 &= 248
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1827:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1828:	r2 = r10
    1829:	r2 += -104
    1830:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1832:	call 1
    1833:	if r0 != 0 goto +61 <LBB5_211>
    1834:	r1 = 72057594037927972 ll
; .ip6 = *addr,
    1836:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1837:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1838:	*(u64 *)(r10 - 88) = r6
    1839:	r1 = r8
    1840:	r1 &= 240
    1841:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1842:	r2 = r10
; return map_lookup_elem(map, &key);
    1843:	r2 += -104
    1844:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1846:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1847:	if r0 != 0 goto +47 <LBB5_211>
    1848:	r1 = 72057594037927971 ll
; .ip6 = *addr,
    1850:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1851:	r6 = 0
; addr->p3 &= GET_PREFIX(prefix);
    1852:	*(u32 *)(r10 - 92) = r6
    1853:	*(u64 *)(r10 - 88) = r6
    1854:	r1 = r8
    1855:	r1 &= 224
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1856:	*(u32 *)(r10 - 96) = r1
; return map_lookup_elem(map, &key);
    1857:	r2 = r10
    1858:	r2 += -104
    1859:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1861:	call 1
    1862:	if r0 != 0 goto +32 <LBB5_211>
    1863:	r1 = 72057594037927970 ll
; .ip6 = *addr,
    1865:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1866:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    1867:	*(u64 *)(r10 - 88) = r6
    1868:	r1 = r8
    1869:	r1 &= 192
    1870:	*(u32 *)(r10 - 96) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1871:	r2 = r10
; return map_lookup_elem(map, &key);
    1872:	r2 += -104
    1873:	r1 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1875:	call 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1876:	if r0 != 0 goto +18 <LBB5_211>
    1877:	r1 = 72057594037927969 ll
; .ip6 = *addr,
    1879:	*(u64 *)(r10 - 104) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1880:	r1 = r8
; addr->p3 &= GET_PREFIX(prefix);
    1881:	r1 &= 128
    1882:	*(u32 *)(r10 - 96) = r1
    1883:	r1 = 0
    1884:	*(u32 *)(r10 - 92) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1885:	*(u64 *)(r10 - 88) = r1
; return map_lookup_elem(map, &key);
    1886:	r2 = r10
    1887:	r2 += -104
    1888:	r1 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1890:	call 1
    1891:	r2 = 0
    1892:	r7 = 52
; .ip6 = *addr,
    1893:	r6 = 2
    1894:	if r0 == 0 goto +7 <LBB5_213>

LBB5_211:
; addr->p4 &= GET_PREFIX(prefix);
    1895:	r7 = 54
; addr->p3 &= GET_PREFIX(prefix);
    1896:	r2 = 0
    1897:	r6 = 2
    1898:	r1 = *(u32 *)(r0 + 0)
    1899:	if r1 == 0 goto +2 <LBB5_213>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1900:	r2 = *(u32 *)(r0 + 4)
; return map_lookup_elem(map, &key);
    1901:	r6 = r1

LBB5_213:
    1902:	*(u64 *)(r10 - 312) = r2
    1903:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1904:	call 34
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1905:	*(u8 *)(r10 - 103) = r7
    1906:	r1 = 2
    1907:	*(u8 *)(r10 - 104) = r1
; .ip6 = *addr,
    1908:	r1 = 4112
; addr->p4 &= GET_PREFIX(prefix);
    1909:	*(u16 *)(r10 - 102) = r1
; addr->p3 &= GET_PREFIX(prefix);
    1910:	*(u32 *)(r10 - 100) = r0
    1911:	*(u32 *)(r10 - 96) = r8
    1912:	r1 = 0
    1913:	*(u32 *)(r10 - 88) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1914:	*(u32 *)(r10 - 92) = r6
; return map_lookup_elem(map, &key);
    1915:	r4 = r10
    1916:	r4 += -104
    1917:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1918:	r2 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1920:	r3 = 4294967295 ll
; .ip6 = *addr,
    1922:	r5 = 20
    1923:	call 25
; addr->p4 &= GET_PREFIX(prefix);
    1924:	r3 = *(u8 *)(r10 - 108)
; addr->p3 &= GET_PREFIX(prefix);
    1925:	r8 = r9
    1926:	r9 = *(u16 *)(r10 - 112)
    1927:	*(u32 *)(r10 - 40) = r6
    1928:	r2 = 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1929:	r1 = 1
; return map_lookup_elem(map, &key);
    1930:	*(u64 *)(r10 - 296) = r1
    1931:	*(u8 *)(r10 - 33) = r2
    1932:	*(u16 *)(r10 - 36) = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1933:	*(u64 *)(r10 - 280) = r3
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1934:	*(u8 *)(r10 - 34) = r3
    1935:	r2 = r10
    1936:	r2 += -40
; .ip6 = *addr,
    1937:	r1 = 0 ll
; addr->p3 &= GET_PREFIX(prefix);
    1939:	call 1
    1940:	r7 = r0
    1941:	*(u64 *)(r10 - 208) = r6
    1942:	if r7 == 0 goto +1562 <LBB5_381>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1943:	r1 = r8
; return map_lookup_elem(map, &key);
    1944:	call 34
    1945:	*(u32 *)(r10 - 100) = r0
    1946:	r1 = 269497090
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1947:	*(u32 *)(r10 - 104) = r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1948:	*(u32 *)(r10 - 96) = r6
    1949:	r1 = 2
    1950:	*(u32 *)(r10 - 92) = r1
; .ip6 = *addr,
    1951:	r9 <<= 16
    1952:	r1 = *(u64 *)(r10 - 280)
; addr->p4 &= GET_PREFIX(prefix);
    1953:	r9 |= r1
; addr->p3 &= GET_PREFIX(prefix);
    1954:	*(u32 *)(r10 - 88) = r9
    1955:	r4 = r10
    1956:	r4 += -104
    1957:	r1 = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1958:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    1960:	r3 = 4294967295 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1962:	r5 = 20
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1963:	call 25
    1964:	r1 = *(u64 *)(r10 - 296)
    1965:	lock *(u64 *)(r7 + 8) += r1
; .ip6 = *addr,
    1966:	r1 = *(u32 *)(r8 + 0)
; addr->p4 &= GET_PREFIX(prefix);
    1967:	lock *(u64 *)(r7 + 16) += r1
; addr->p3 &= GET_PREFIX(prefix);
    1968:	r9 = r8

LBB5_215:
    1969:	r3 = *(u16 *)(r7 + 0)

LBB5_216:
    1970:	r4 = *(u64 *)(r10 - 208)
    1971:	r6 = *(u64 *)(r10 - 264)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1972:	r8 = *(u64 *)(r10 - 248)

LBB5_217:
; return map_lookup_elem(map, &key);
    1973:	r1 = r6
    1974:	r1 &= 255
    1975:	r2 = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1976:	r2 += -2
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1977:	if r2 < 2 goto +89 <LBB5_231>
    1978:	if r1 == 1 goto +219 <LBB5_242>
    1979:	r7 = 4294967163 ll
; .ip6 = *addr,
    1981:	if r1 != 0 goto +1466 <LBB5_373>
; addr->p4 &= GET_PREFIX(prefix);
    1982:	r1 = *(u8 *)(r10 - 108)
; addr->p3 &= GET_PREFIX(prefix);
    1983:	r2 = 0
    1984:	*(u64 *)(r10 - 72) = r2
    1985:	*(u64 *)(r10 - 64) = r2
    1986:	*(u64 *)(r10 - 56) = r2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1987:	*(u64 *)(r10 - 80) = r2
; return map_lookup_elem(map, &key);
    1988:	*(u64 *)(r10 - 88) = r2
    1989:	*(u64 *)(r10 - 96) = r2
    1990:	*(u64 *)(r10 - 104) = r2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1991:	r2 = *(u64 *)(r10 - 240)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1992:	*(u16 *)(r10 - 66) = r2
    1993:	r2 = *(u64 *)(r10 - 224)
    1994:	*(u16 *)(r10 - 64) = r2
; .ip6 = *addr,
    1995:	r7 = 0 ll
; addr->p3 &= GET_PREFIX(prefix);
    1997:	if r1 == 6 goto +2 <LBB5_222>
    1998:	r7 = 0 ll

LBB5_222:
    2000:	*(u64 *)(r10 - 224) = r3
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2001:	r6 = *(u64 *)(r10 - 272)
; return map_lookup_elem(map, &key);
    2002:	r6 <<= 3
    2003:	*(u16 *)(r10 - 68) = r6
    2004:	if r1 != 6 goto +1 <LBB5_224>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2005:	*(u16 *)(r10 - 68) = r6

LBB5_224:
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2006:	call 5
    2007:	r0 /= 1000000000
    2008:	r1 = r0
; .ip6 = *addr,
    2009:	r1 += 60
    2010:	*(u32 *)(r10 - 72) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2011:	r1 = r0
    2012:	r1 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2013:	r1 >>= 32
; return map_lookup_elem(map, &key);
    2014:	r2 = *(u32 *)(r10 - 56)
    2015:	r2 += 5
    2016:	r2 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2017:	r2 >>= 32
; .ip6 = *addr,
    2018:	if r2 >= r1 goto +1 <LBB5_226>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2019:	*(u32 *)(r10 - 56) = r0

LBB5_226:
    2020:	r1 = 1
    2021:	*(u64 *)(r10 - 88) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2022:	r1 = *(u32 *)(r9 + 0)
; addr->p2 &= GET_PREFIX(prefix);
    2023:	*(u64 *)(r10 - 80) = r1
    2024:	r1 = *(u32 *)(r9 + 60)
    2025:	if r1 != 1 goto +2 <LBB5_228>
    2026:	r6 |= 4
    2027:	*(u16 *)(r10 - 68) = r6

LBB5_228:
    2028:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2029:	call 34
; return map_lookup_elem(map, &key);
    2030:	*(u32 *)(r10 - 36) = r0
    2031:	r1 = 269495810
    2032:	*(u32 *)(r10 - 40) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2033:	r1 = *(u64 *)(r10 - 240)
; .ip6 = *addr,
    2034:	r1 &= 65535
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2035:	*(u32 *)(r10 - 32) = r1
    2036:	*(u32 *)(r10 - 24) = r8
    2037:	r6 = 2
    2038:	*(u32 *)(r10 - 28) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2039:	r4 = r10
; addr->p2 &= GET_PREFIX(prefix);
    2040:	r4 += -40
    2041:	r1 = r9
    2042:	r2 = 0 ll
    2044:	r3 = 4294967295 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2046:	r5 = 20
; return map_lookup_elem(map, &key);
    2047:	call 25
    2048:	*(u32 *)(r10 - 60) = r6
    2049:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2050:	r2 += -120
; .ip6 = *addr,
    2051:	r3 = r10
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2052:	r3 += -104
    2053:	r1 = r7
    2054:	r4 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2055:	call 2
; addr->p2 &= GET_PREFIX(prefix);
    2056:	r0 <<= 32
    2057:	r0 s>>= 32
    2058:	if r0 s< 0 goto +371 <LBB5_263>
    2059:	r1 = r8
    2060:	r1 <<= 32
    2061:	r1 >>= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2062:	if r1 != 0 goto +84 <LBB5_237>
; return map_lookup_elem(map, &key);
    2063:	r8 = *(u8 *)(r10 - 107)
    2064:	r9 = *(u32 *)(r10 - 116)
    2065:	r6 = *(u32 *)(r10 - 120)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2066:	goto +103 <LBB5_241>

LBB5_231:
; .ip6 = *addr,
    2067:	r1 = 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2068:	*(u32 *)(r9 + 56) = r1
    2069:	r6 = *(u16 *)(r10 - 160)
    2070:	if r6 == 0 goto +625 <LBB5_306>
    2071:	r1 = r9
; addr->p3 &= GET_PREFIX(prefix);
    2072:	call 34
; addr->p2 &= GET_PREFIX(prefix);
    2073:	*(u32 *)(r10 - 100) = r0
    2074:	r1 = 269492226
    2075:	*(u32 *)(r10 - 104) = r1
    2076:	*(u32 *)(r10 - 96) = r6
    2077:	r1 = 0
    2078:	*(u32 *)(r10 - 92) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2079:	*(u32 *)(r10 - 88) = r1
; return map_lookup_elem(map, &key);
    2080:	r4 = r10
    2081:	r4 += -104
    2082:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2083:	r2 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2085:	r3 = 4294967295 ll
    2087:	r5 = 20
; addr->p3 &= GET_PREFIX(prefix);
    2088:	call 25
; addr->p2 &= GET_PREFIX(prefix);
    2089:	r2 = r10
    2090:	r2 += -160
    2091:	r1 = 0 ll
    2093:	call 1
    2094:	r7 = 0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2095:	if r0 == 0 goto +589 <LBB5_303>
; return map_lookup_elem(map, &key);
    2096:	r7 = *(u8 *)(r0 + 5)
    2097:	r7 <<= 8
    2098:	r1 = *(u8 *)(r0 + 4)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2099:	r7 |= r1
; .ip6 = *addr,
    2100:	r1 = *(u8 *)(r0 + 2)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2101:	*(u64 *)(r10 - 224) = r1
    2102:	*(u64 *)(r10 - 216) = r0
    2103:	r6 = *(u8 *)(r0 + 3)
    2104:	r9 = *(u8 *)(r0 + 0)
; addr->p3 &= GET_PREFIX(prefix);
    2105:	r8 = *(u8 *)(r0 + 1)
; addr->p2 &= GET_PREFIX(prefix);
    2106:	r1 = *(u64 *)(r10 - 192)
    2107:	call 34
    2108:	*(u32 *)(r10 - 100) = r0
    2109:	r1 = 269492482
    2110:	*(u32 *)(r10 - 104) = r1
    2111:	*(u32 *)(r10 - 92) = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2112:	r1 = 0
; return map_lookup_elem(map, &key);
    2113:	*(u32 *)(r10 - 88) = r1
    2114:	r8 <<= 8
    2115:	r8 |= r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2116:	r9 = *(u64 *)(r10 - 192)
; .ip6 = *addr,
    2117:	r6 <<= 8
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2118:	r1 = *(u64 *)(r10 - 224)
    2119:	r6 |= r1
    2120:	r6 <<= 16
; addr->p3 &= GET_PREFIX(prefix);
    2121:	r6 |= r8
; addr->p2 &= GET_PREFIX(prefix);
    2122:	*(u32 *)(r10 - 96) = r6
    2123:	r4 = r10
    2124:	r4 += -104
    2125:	r1 = r9
    2126:	r2 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2128:	r3 = 4294967295 ll
; return map_lookup_elem(map, &key);
    2130:	r5 = 20
    2131:	call 25
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2132:	r2 = *(u64 *)(r10 - 216)
; .ip6 = *addr,
    2133:	r1 = *(u8 *)(r2 + 4)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2134:	r6 = r2
    2135:	r8 = *(u8 *)(r2 + 5)
    2136:	r8 <<= 8
    2137:	r8 |= r1
; addr->p3 &= GET_PREFIX(prefix);
    2138:	r1 = *(u64 *)(r10 - 200)
; addr->p2 &= GET_PREFIX(prefix);
    2139:	if r8 == 0 goto +392 <LBB5_284>
    2140:	r7 = 4294967154 ll
    2142:	r1 = *(u8 *)(r10 - 108)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2143:	if r1 s> 16 goto +320 <LBB5_268>
; return map_lookup_elem(map, &key);
    2144:	if r1 == 1 goto +377 <LBB5_280>
    2145:	if r1 == 6 goto +320 <LBB5_270>
    2146:	goto +376 <LBB5_281>

LBB5_237:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2147:	r6 = *(u32 *)(r10 - 120)
; .ip6 = *addr,
    2148:	*(u32 *)(r10 - 120) = r8
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2149:	r9 = *(u32 *)(r10 - 116)
    2150:	r8 = *(u8 *)(r10 - 107)
    2151:	r1 = *(u64 *)(r10 - 272)
; addr->p3 &= GET_PREFIX(prefix);
    2152:	if r1 == 0 goto +4 <LBB5_239>
; addr->p2 &= GET_PREFIX(prefix);
    2153:	r1 = *(u64 *)(r10 - 288)
    2154:	*(u32 *)(r10 - 116) = r1
    2155:	r1 = 1
    2156:	*(u8 *)(r10 - 107) = r1

LBB5_239:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2157:	r2 = r10
; return map_lookup_elem(map, &key);
    2158:	r2 += -120
    2159:	r3 = r10
    2160:	r3 += -104
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2161:	r1 = r7
; .ip6 = *addr,
    2162:	r4 = 0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2163:	call 2
    2164:	r0 <<= 32
    2165:	r0 s>>= 32
    2166:	if r0 s< 0 goto +263 <LBB5_263>
; addr->p3 &= GET_PREFIX(prefix);
    2167:	*(u32 *)(r10 - 120) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2168:	*(u32 *)(r10 - 116) = r9
    2169:	*(u8 *)(r10 - 107) = r8

LBB5_241:
    2170:	*(u32 *)(r10 - 36) = r9
    2171:	*(u32 *)(r10 - 40) = r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2172:	r1 = 1
; return map_lookup_elem(map, &key);
    2173:	*(u8 *)(r10 - 28) = r1
    2174:	r8 |= 2
    2175:	*(u8 *)(r10 - 27) = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2176:	r1 = *(u16 *)(r10 - 68)
; .ip6 = *addr,
    2177:	r1 |= 16
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2178:	*(u16 *)(r10 - 68) = r1
    2179:	r1 = 0
    2180:	*(u32 *)(r10 - 32) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2181:	r2 = r10
; addr->p2 &= GET_PREFIX(prefix);
    2182:	r2 += -40
    2183:	r3 = r10
    2184:	r3 += -104
    2185:	r1 = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2186:	r4 = 0
; return map_lookup_elem(map, &key);
    2187:	call 2
    2188:	r0 <<= 32
    2189:	r7 = r0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2190:	r7 s>>= 63
; .ip6 = *addr,
    2191:	r7 &= -155
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2192:	r0 s>>= 32
    2193:	r9 = *(u64 *)(r10 - 192)
    2194:	r4 = *(u64 *)(r10 - 208)
    2195:	r3 = *(u64 *)(r10 - 224)
; addr->p3 &= GET_PREFIX(prefix);
    2196:	if r0 s> -1 goto +1 <LBB5_242>
; addr->p2 &= GET_PREFIX(prefix);
    2197:	goto +1250 <LBB5_373>

LBB5_242:
    2198:	r1 = r3
    2199:	r1 <<= 32
    2200:	r1 s>>= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2201:	if r1 s< 1 goto +494 <LBB5_306>
; return map_lookup_elem(map, &key);
    2202:	r1 = 95142176846542 ll
    2204:	*(u64 *)(r10 - 8) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2205:	r7 = *(u16 *)(r10 - 112)
; .ip6 = *addr,
    2206:	r1 = 4294964490 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2208:	*(u32 *)(r10 - 44) = r1
    2209:	*(u64 *)(r10 - 224) = r3
; addr->p3 &= GET_PREFIX(prefix);
    2210:	*(u16 *)(r10 - 180) = r3
; addr->p2 &= GET_PREFIX(prefix);
    2211:	r1 = *(u32 *)(r10 - 120)
    2212:	*(u32 *)(r10 - 184) = r1
    2213:	r1 = *(u16 *)(r10 - 110)
    2214:	*(u16 *)(r10 - 178) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2215:	r1 = *(u8 *)(r10 - 108)
; return map_lookup_elem(map, &key);
    2216:	*(u8 *)(r10 - 176) = r1
    2217:	r6 = 0
    2218:	*(u8 *)(r10 - 175) = r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2219:	r1 = *(u64 *)(r10 - 216)
; .ip6 = *addr,
    2220:	*(u32 *)(r10 - 40) = r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2221:	*(u16 *)(r10 - 34) = r6
    2222:	r1 = 2
    2223:	*(u32 *)(r10 - 32) = r1
    2224:	*(u16 *)(r10 - 36) = r7
; addr->p3 &= GET_PREFIX(prefix);
    2225:	call 5
; addr->p2 &= GET_PREFIX(prefix);
    2226:	r0 /= 1000000000
    2227:	r0 += 720
    2228:	*(u32 *)(r10 - 28) = r0
    2229:	r8 = *(u64 *)(r10 - 304)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2230:	r8 <<= 32
; return map_lookup_elem(map, &key);
    2231:	r8 >>= 32
    2232:	if r8 == 0 goto +31 <LBB5_247>
    2233:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2234:	r9 = *(u32 *)(r1 + 0)
; .ip6 = *addr,
    2235:	call 34
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2236:	*(u32 *)(r10 - 100) = r0
    2237:	r1 = 269484292
    2238:	*(u32 *)(r10 - 104) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2239:	r1 = 2
; addr->p2 &= GET_PREFIX(prefix);
    2240:	*(u64 *)(r10 - 88) = r1
    2241:	r1 = *(u64 *)(r10 - 264)
    2242:	*(u8 *)(r10 - 78) = r1
    2243:	*(u16 *)(r10 - 80) = r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2244:	*(u8 *)(r10 - 77) = r6
; return map_lookup_elem(map, &key);
    2245:	r1 = 1
    2246:	*(u32 *)(r10 - 76) = r1
    2247:	*(u32 *)(r10 - 96) = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2248:	if r8 < r9 goto +1 <LBB5_246>
; .ip6 = *addr,
    2249:	r8 = r9

LBB5_246:
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2250:	*(u32 *)(r10 - 92) = r8
    2251:	r8 <<= 32
    2252:	r1 = 4294967295 ll
; addr->p3 &= GET_PREFIX(prefix);
    2254:	r8 |= r1
; addr->p2 &= GET_PREFIX(prefix);
    2255:	r4 = r10
    2256:	r4 += -104
    2257:	r9 = *(u64 *)(r10 - 192)
    2258:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2259:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    2261:	r3 = r8
    2262:	r5 = 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2263:	call 25

LBB5_247:
; .ip6 = *addr,
    2264:	r8 = *(u64 *)(r10 - 256)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2265:	r8 &= 65535
    2266:	r6 = *(u64 *)(r10 - 200)
    2267:	r8 += r6
; addr->p3 &= GET_PREFIX(prefix);
    2268:	r4 = *(u64 *)(r10 - 224)
; addr->p2 &= GET_PREFIX(prefix);
    2269:	*(u16 *)(r10 - 104) = r4
    2270:	r4 &= 65535
    2271:	r5 = *(u64 *)(r10 - 232)
    2272:	r5 |= 2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2273:	r5 &= 65535
; return map_lookup_elem(map, &key);
    2274:	r1 = r9
    2275:	r2 = r8
    2276:	r3 = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2277:	*(u64 *)(r10 - 224) = r4
; .ip6 = *addr,
    2278:	call 11
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2279:	r0 <<= 32
    2280:	r0 s>>= 32
    2281:	if r0 s> -1 goto +3 <LBB5_249>
    2282:	r7 = 4294967155 ll
; addr->p2 &= GET_PREFIX(prefix);
    2284:	goto +107 <LBB5_257>

LBB5_249:
    2285:	r6 += 2
    2286:	r3 = r10
    2287:	r3 += -104
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2288:	r1 = r9
; return map_lookup_elem(map, &key);
    2289:	r2 = r6
    2290:	r4 = 2
    2291:	r5 = 0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2292:	call 9
; .ip6 = *addr,
    2293:	r7 = 4294967155 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2295:	r0 <<= 32
    2296:	r0 s>>= 32
; addr->p3 &= GET_PREFIX(prefix);
    2297:	if r0 s< 0 goto +94 <LBB5_257>
; addr->p2 &= GET_PREFIX(prefix);
    2298:	r3 = r10
    2299:	r3 += -44
    2300:	r1 = r9
    2301:	r2 = 30
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2302:	r4 = 4
; return map_lookup_elem(map, &key);
    2303:	r5 = 0
    2304:	call 9
    2305:	r0 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2306:	r0 s>>= 32
; .ip6 = *addr,
    2307:	if r0 s< 0 goto +84 <LBB5_257>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2308:	r4 = *(u32 *)(r10 - 44)
    2309:	r1 = r9
    2310:	r2 = 24
    2311:	r3 = *(u64 *)(r10 - 216)
; addr->p3 &= GET_PREFIX(prefix);
    2312:	r5 = 4
; addr->p2 &= GET_PREFIX(prefix);
    2313:	call 10
    2314:	r7 = 4294967143 ll
    2316:	r0 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2317:	r0 s>>= 32
; return map_lookup_elem(map, &key);
    2318:	if r0 s< 0 goto +73 <LBB5_257>
    2319:	r1 = *(u64 *)(r10 - 256)
    2320:	if r1 == 0 goto +13 <LBB5_254>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2321:	r4 = *(u32 *)(r10 - 44)
; .ip6 = *addr,
    2322:	r5 = *(u64 *)(r10 - 232)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2323:	r5 |= 20
    2324:	r5 &= 65535
    2325:	r1 = r9
; addr->p3 &= GET_PREFIX(prefix);
    2326:	r2 = r8
; addr->p2 &= GET_PREFIX(prefix);
    2327:	r3 = *(u64 *)(r10 - 216)
    2328:	call 11
    2329:	r7 = 4294967142 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2331:	r0 <<= 32
; return map_lookup_elem(map, &key);
    2332:	r0 s>>= 32
    2333:	if r0 s< 0 goto +58 <LBB5_257>

LBB5_254:
    2334:	r7 = *(u32 *)(r9 + 0)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2335:	r1 = r9
; .ip6 = *addr,
    2336:	call 34
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2337:	*(u32 *)(r10 - 100) = r0
    2338:	r1 = 269486339
    2339:	*(u32 *)(r10 - 104) = r1
    2340:	r1 = *(u64 *)(r10 - 224)
; addr->p3 &= GET_PREFIX(prefix);
    2341:	*(u32 *)(r10 - 88) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2342:	*(u32 *)(r10 - 96) = r7
    2343:	if r7 < 128 goto +1 <LBB5_256>
    2344:	r7 = 128

LBB5_256:
    2345:	*(u32 *)(r10 - 92) = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2346:	r1 = 0
; return map_lookup_elem(map, &key);
    2347:	*(u32 *)(r10 - 84) = r1
    2348:	r7 <<= 32
    2349:	r1 = 4294967295 ll
; .ip6 = *addr,
    2351:	r7 |= r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2352:	r4 = r10
    2353:	r4 += -104
    2354:	r1 = r9
; addr->p3 &= GET_PREFIX(prefix);
    2355:	r2 = 0 ll
; addr->p2 &= GET_PREFIX(prefix);
    2357:	r3 = r7
    2358:	r5 = 24
    2359:	call 25
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2360:	r6 = *(u8 *)(r10 - 176)
; return map_lookup_elem(map, &key);
    2361:	r7 = *(u32 *)(r10 - 184)
    2362:	r8 = *(u32 *)(r10 - 180)
    2363:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2364:	call 34
; .ip6 = *addr,
    2365:	*(u32 *)(r10 - 100) = r0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2366:	r1 = 269494274
    2367:	*(u32 *)(r10 - 104) = r1
    2368:	*(u32 *)(r10 - 96) = r8
    2369:	*(u32 *)(r10 - 92) = r7
; addr->p3 &= GET_PREFIX(prefix);
    2370:	*(u32 *)(r10 - 88) = r6
; addr->p2 &= GET_PREFIX(prefix);
    2371:	r4 = r10
    2372:	r4 += -104
    2373:	r1 = r9
    2374:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    2376:	r3 = 4294967295 ll
    2378:	r5 = 20
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2379:	call 25
; .ip6 = *addr,
    2380:	r2 = r10
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2381:	r2 += -184
    2382:	r3 = r10
    2383:	r3 += -40
; addr->p3 &= GET_PREFIX(prefix);
    2384:	r1 = 0 ll
; addr->p2 &= GET_PREFIX(prefix);
    2386:	r4 = 0
    2387:	call 2
    2388:	r7 = r0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2389:	r7 <<= 32
; return map_lookup_elem(map, &key);
    2390:	r7 s>>= 63
    2391:	r7 &= -161

LBB5_257:
    2392:	r1 = r7
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2393:	r1 <<= 32
; .ip6 = *addr,
    2394:	r1 >>= 32
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2395:	r2 = 1
    2396:	if r1 == 2 goto +1 <LBB5_259>
    2397:	r2 = 0

LBB5_259:
    2398:	r1 >>= 31
; addr->p3 &= GET_PREFIX(prefix);
    2399:	r1 |= r2
; addr->p2 &= GET_PREFIX(prefix);
    2400:	if r1 != 0 goto +1046 <LBB5_372>
    2401:	r7 = 4294967162 ll
    2403:	r1 = *(u32 *)(r9 + 80)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2404:	r6 = *(u32 *)(r9 + 76)
; return map_lookup_elem(map, &key);
    2405:	r2 = r6
    2406:	r2 += 34
    2407:	if r2 > r1 goto +1039 <LBB5_372>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2408:	r8 = *(u32 *)(r9 + 56)
; .ip6 = *addr,
    2409:	r1 = r9
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2410:	call 34
    2411:	*(u32 *)(r10 - 100) = r0
    2412:	r1 = 269488898
; addr->p3 &= GET_PREFIX(prefix);
    2413:	*(u32 *)(r10 - 104) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2414:	*(u32 *)(r10 - 96) = r8
    2415:	r1 = 0
    2416:	*(u32 *)(r10 - 92) = r1
    2417:	*(u32 *)(r10 - 88) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2418:	r4 = r10
; return map_lookup_elem(map, &key);
    2419:	r4 += -104
    2420:	r1 = r9
    2421:	r2 = 0 ll
; .ip6 = *addr,
    2423:	r3 = 4294967295 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2425:	r5 = 20
    2426:	call 25
    2427:	r3 = *(u8 *)(r6 + 22)
; addr->p3 &= GET_PREFIX(prefix);
    2428:	if r3 > 1 goto +949 <LBB5_365>
; addr->p2 &= GET_PREFIX(prefix);
    2429:	goto +1017 <LBB5_372>

LBB5_263:
    2430:	r7 = 4294967141 ll
    2432:	r9 = *(u64 *)(r10 - 192)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2433:	goto +1013 <LBB5_372>

LBB5_264:
; return map_lookup_elem(map, &key);
    2434:	r1 = *(u16 *)(r7 + 36)
    2435:	r1 |= 2
    2436:	*(u16 *)(r7 + 36) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2437:	r2 = 128
; .ip6 = *addr,
    2438:	*(u64 *)(r10 - 208) = r2
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2439:	r1 &= 3
    2440:	if r1 != 3 goto -837 <LBB5_191>
    2441:	call 5
; addr->p3 &= GET_PREFIX(prefix);
    2442:	r0 /= 1000000000
; addr->p2 &= GET_PREFIX(prefix);
    2443:	r1 = r0
    2444:	r1 += 10
    2445:	*(u32 *)(r7 + 32) = r1
    2446:	r2 = *(u8 *)(r7 + 42)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2447:	r1 = r2
; return map_lookup_elem(map, &key);
    2448:	r3 = *(u64 *)(r10 - 304)
    2449:	r1 |= r3
    2450:	r3 = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2451:	r3 &= 255
; .ip6 = *addr,
    2452:	if r2 != r3 goto +8 <LBB5_267>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2453:	r2 = *(u32 *)(r7 + 48)
    2454:	r2 += 5
    2455:	r3 = r0
    2456:	r3 <<= 32
; addr->p3 &= GET_PREFIX(prefix);
    2457:	r3 >>= 32
; addr->p2 &= GET_PREFIX(prefix);
    2458:	r2 <<= 32
    2459:	r2 >>= 32
    2460:	if r2 >= r3 goto -857 <LBB5_191>

LBB5_267:
    2461:	*(u8 *)(r7 + 42) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2462:	*(u32 *)(r7 + 48) = r0
; return map_lookup_elem(map, &key);
    2463:	goto -860 <LBB5_191>

LBB5_268:
    2464:	if r1 == 58 goto +57 <LBB5_280>
    2465:	if r1 != 17 goto +57 <LBB5_281>

LBB5_270:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2466:	r3 = r10
; .ip6 = *addr,
    2467:	r3 += -40
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2468:	r1 = r9
    2469:	r2 = *(u64 *)(r10 - 200)
    2470:	r4 = 2
; addr->p3 &= GET_PREFIX(prefix);
    2471:	call 26
    2472:	r7 = r0
; addr->p2 &= GET_PREFIX(prefix);
    2473:	r1 = r7
    2474:	r1 <<= 32
    2475:	r1 >>= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2476:	r2 = 1
; return map_lookup_elem(map, &key);
    2477:	if r1 == 2 goto +1 <LBB5_272>
    2478:	r2 = 0

LBB5_272:
    2479:	r1 >>= 31
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2480:	r1 |= r2
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2481:	if r1 != 0 goto +39 <LBB5_279>
    2482:	r3 = *(u16 *)(r10 - 40)
    2483:	if r3 == r8 goto +38 <LBB5_280>
; .ip6 = *addr,
    2484:	r2 = *(u64 *)(r10 - 256)
    2485:	r2 &= 65535
    2486:	r0 = *(u64 *)(r10 - 200)
; addr->p2 &= GET_PREFIX(prefix);
    2487:	r2 += r0
; addr->p3 &= GET_PREFIX(prefix);
    2488:	*(u16 *)(r10 - 104) = r8
    2489:	r5 = *(u64 *)(r10 - 232)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2490:	r5 |= 2
; return map_lookup_elem(map, &key);
    2491:	r5 &= 65535
    2492:	r1 = r9
    2493:	r4 = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2494:	r8 = r0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2495:	call 11
    2496:	r7 = 4294967142 ll
; addr->p2 &= GET_PREFIX(prefix);
    2498:	r0 <<= 32
; addr->p3 &= GET_PREFIX(prefix);
    2499:	r0 s>>= 32
; addr->p1 &= GET_PREFIX(prefix);
    2500:	if r0 s< 0 goto +11 <LBB5_276>
    2501:	r3 = r10
    2502:	r3 += -104
    2503:	r1 = r9
    2504:	r2 = r8
    2505:	r4 = 2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2506:	r5 = 0
; return map_lookup_elem(map, &key);
    2507:	call 9
    2508:	r7 = r0
    2509:	r7 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2510:	r7 s>>= 63
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2511:	r7 &= -141

LBB5_276:
    2512:	r1 = r7
    2513:	r1 <<= 32
    2514:	r1 >>= 32
; addr->p2 &= GET_PREFIX(prefix);
    2515:	r2 = 1
; addr->p3 &= GET_PREFIX(prefix);
    2516:	if r1 == 2 goto +1 <LBB5_278>
; addr->p1 &= GET_PREFIX(prefix);
    2517:	r2 = 0

LBB5_278:
    2518:	r1 >>= 31
    2519:	r1 |= r2
    2520:	if r1 == 0 goto +1 <LBB5_280>

LBB5_279:
    2521:	goto +1 <LBB5_281>

LBB5_280:
    2522:	r7 = 0

LBB5_281:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2523:	r1 = r7
; return map_lookup_elem(map, &key);
    2524:	r1 <<= 32
    2525:	r1 >>= 32
    2526:	r2 = 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2527:	if r1 == 2 goto +1 <LBB5_283>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2528:	r2 = 0

LBB5_283:
    2529:	r1 >>= 31
    2530:	r1 |= r2
; addr->p2 &= GET_PREFIX(prefix);
    2531:	if r1 != 0 goto +153 <LBB5_303>

LBB5_284:
; addr->p3 &= GET_PREFIX(prefix);
    2532:	r3 = r10
; addr->p1 &= GET_PREFIX(prefix);
    2533:	r3 += -40
    2534:	r1 = r9
    2535:	r2 = 26
    2536:	r4 = 4
    2537:	call 26
    2538:	r7 = r0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2539:	r1 = r7
; return map_lookup_elem(map, &key);
    2540:	r1 <<= 32
    2541:	r1 >>= 32
    2542:	r2 = 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2543:	if r1 == 2 goto +1 <LBB5_286>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2544:	r2 = 0

LBB5_286:
    2545:	r1 >>= 31
    2546:	r1 |= r2
    2547:	if r1 != 0 goto +137 <LBB5_303>
; addr->p2 &= GET_PREFIX(prefix);
    2548:	r1 = *(u8 *)(r6 + 1)
; addr->p3 &= GET_PREFIX(prefix);
    2549:	r1 <<= 8
; addr->p1 &= GET_PREFIX(prefix);
    2550:	r2 = *(u8 *)(r6 + 0)
    2551:	r1 |= r2
    2552:	r2 = *(u8 *)(r6 + 2)
    2553:	r3 = *(u8 *)(r6 + 3)
    2554:	r3 <<= 8
    2555:	r3 |= r2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2556:	r3 <<= 16
; return map_lookup_elem(map, &key);
    2557:	r3 |= r1
    2558:	*(u32 *)(r10 - 184) = r3
    2559:	r1 = *(u8 *)(r10 - 158)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2560:	r1 &= 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2561:	r8 = 0
    2562:	if r1 == 0 goto +66 <LBB5_296>
    2563:	r3 = r10
; addr->p2 &= GET_PREFIX(prefix);
    2564:	r3 += -8
; addr->p3 &= GET_PREFIX(prefix);
    2565:	r1 = r9
; addr->p1 &= GET_PREFIX(prefix);
    2566:	r2 = 30
    2567:	r4 = 4
    2568:	call 26
    2569:	r7 = r0
    2570:	r1 = r7
    2571:	r1 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2572:	r1 >>= 32
; return map_lookup_elem(map, &key);
    2573:	r2 = 1
    2574:	if r1 == 2 goto +1 <LBB5_290>
    2575:	r2 = 0

LBB5_290:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2576:	r1 >>= 31
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2577:	r1 |= r2
    2578:	if r1 != 0 goto +38 <LBB5_294>
    2579:	r6 = *(u32 *)(r10 - 40)
    2580:	r7 = *(u32 *)(r10 - 8)
; addr->p2 &= GET_PREFIX(prefix);
    2581:	r1 = r9
; addr->p3 &= GET_PREFIX(prefix);
    2582:	call 34
; addr->p1 &= GET_PREFIX(prefix);
    2583:	*(u32 *)(r10 - 100) = r0
    2584:	r1 = 269492994
    2585:	*(u32 *)(r10 - 104) = r1
    2586:	*(u32 *)(r10 - 96) = r7
    2587:	*(u32 *)(r10 - 92) = r6
    2588:	r1 = 0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2589:	*(u32 *)(r10 - 88) = r1
; return map_lookup_elem(map, &key);
    2590:	r4 = r10
    2591:	r4 += -104
    2592:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2593:	r2 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2595:	r3 = 4294967295 ll
; addr->p2 &= GET_PREFIX(prefix);
    2597:	r5 = 20
; addr->p3 &= GET_PREFIX(prefix);
    2598:	call 25
; addr->p1 &= GET_PREFIX(prefix);
    2599:	r3 = r10
    2600:	r3 += -40
    2601:	r1 = r9
    2602:	r2 = 30
    2603:	r4 = 4
    2604:	r5 = 0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2605:	call 9
; return map_lookup_elem(map, &key);
    2606:	r0 <<= 32
    2607:	r0 >>= 32
    2608:	r1 = 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2609:	if r0 == 2 goto +1 <LBB5_293>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2610:	r1 = 0

LBB5_293:
    2611:	r0 >>= 31
    2612:	r0 |= r1
    2613:	r7 = 4294967155 ll
; addr->p3 &= GET_PREFIX(prefix);
    2615:	r1 = *(u64 *)(r10 - 200)
; addr->p1 &= GET_PREFIX(prefix);
    2616:	if r0 == 0 goto +1 <LBB5_295>

LBB5_294:
    2617:	goto +67 <LBB5_303>

LBB5_295:
    2618:	r1 = r10
    2619:	r1 += -8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2620:	r3 = r10
; return map_lookup_elem(map, &key);
    2621:	r3 += -40
    2622:	r2 = 4
    2623:	r4 = 4
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2624:	r5 = 0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2625:	call 28
    2626:	r8 = r0
    2627:	r1 = *(u32 *)(r10 - 40)
; addr->p2 &= GET_PREFIX(prefix);
    2628:	*(u32 *)(r10 - 116) = r1

LBB5_296:
; addr->p3 &= GET_PREFIX(prefix);
    2629:	r3 = r10
; addr->p1 &= GET_PREFIX(prefix);
    2630:	r3 += -184
    2631:	r1 = r9
    2632:	r2 = 26
    2633:	r4 = 4
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2634:	r5 = 0
; return map_lookup_elem(map, &key);
    2635:	call 9
    2636:	r0 <<= 32
    2637:	r0 >>= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2638:	r1 = 1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2639:	if r0 == 2 goto +1 <LBB5_298>
    2640:	r1 = 0

LBB5_298:
    2641:	r0 >>= 31
    2642:	r0 |= r1
; addr->p2 &= GET_PREFIX(prefix);
    2643:	r7 = 4294967155 ll
; addr->p1 &= GET_PREFIX(prefix);
    2645:	if r0 != 0 goto +39 <LBB5_303>
    2646:	r1 = r10
    2647:	r1 += -40
    2648:	r3 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2649:	r3 += -184
; return map_lookup_elem(map, &key);
    2650:	r2 = 4
    2651:	r4 = 4
    2652:	r5 = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2653:	call 28
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2654:	r8 = r0
    2655:	r1 = r9
    2656:	r2 = 24
; addr->p2 &= GET_PREFIX(prefix);
    2657:	r3 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2658:	r4 = r8
; addr->p1 &= GET_PREFIX(prefix);
    2659:	r5 = 0
    2660:	call 10
    2661:	r7 = 4294967143 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2663:	r0 <<= 32
; return map_lookup_elem(map, &key);
    2664:	r0 s>>= 32
    2665:	if r0 s< 0 goto +19 <LBB5_303>
    2666:	r1 = *(u64 *)(r10 - 256)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2667:	if r1 == 0 goto +16 <LBB5_302>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2668:	r2 = *(u64 *)(r10 - 256)
    2669:	r2 &= 65535
    2670:	r1 = *(u64 *)(r10 - 200)
    2671:	r2 += r1
; addr->p2 &= GET_PREFIX(prefix);
    2672:	r5 = *(u64 *)(r10 - 232)
; addr->p3 &= GET_PREFIX(prefix);
    2673:	r5 |= 16
; addr->p1 &= GET_PREFIX(prefix);
    2674:	r5 &= 65535
    2675:	r1 = r9
    2676:	r3 = 0
    2677:	r4 = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2678:	call 11
; return map_lookup_elem(map, &key);
    2679:	r7 = 4294967142 ll
    2681:	r0 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2682:	r0 s>>= 32
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2683:	if r0 s< 0 goto +1 <LBB5_303>

LBB5_302:
    2684:	r7 = 0

LBB5_303:
    2685:	r1 = r7
; addr->p2 &= GET_PREFIX(prefix);
    2686:	r1 <<= 32
; addr->p3 &= GET_PREFIX(prefix);
    2687:	r1 >>= 32
; addr->p1 &= GET_PREFIX(prefix);
    2688:	r2 = 1
    2689:	if r1 == 2 goto +1 <LBB5_305>
    2690:	r2 = 0

LBB5_305:
    2691:	r1 >>= 31
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2692:	r1 |= r2
; return map_lookup_elem(map, &key);
    2693:	r4 = *(u64 *)(r10 - 208)
    2694:	if r1 == 0 goto +1 <LBB5_306>
    2695:	goto +752 <LBB5_373>

LBB5_306:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2696:	r1 = *(u32 *)(r9 + 80)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2697:	r3 = *(u32 *)(r9 + 76)
    2698:	r2 = r3
    2699:	r2 += 34
    2700:	r7 = 4294967162 ll
; addr->p3 &= GET_PREFIX(prefix);
    2702:	if r2 > r1 goto +745 <LBB5_373>
; addr->p1 &= GET_PREFIX(prefix);
    2703:	*(u64 *)(r10 - 200) = r3
    2704:	r6 = *(u32 *)(r3 + 30)
    2705:	r1 = 0
    2706:	*(u32 *)(r10 - 88) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2707:	*(u32 *)(r10 - 92) = r1
; return map_lookup_elem(map, &key);
    2708:	*(u32 *)(r10 - 96) = r1
    2709:	*(u32 *)(r10 - 100) = r1
    2710:	r1 = 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2711:	*(u8 *)(r10 - 88) = r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2712:	*(u32 *)(r10 - 104) = r6
    2713:	r2 = r10
    2714:	r2 += -104
; addr->p2 &= GET_PREFIX(prefix);
    2715:	r1 = 0 ll
; addr->p1 &= GET_PREFIX(prefix);
    2717:	call 1
    2718:	r8 = r0
    2719:	if r8 == 0 goto +34 <LBB5_311>
    2720:	r1 = *(u8 *)(r8 + 8)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2721:	r1 &= 1
; return map_lookup_elem(map, &key);
    2722:	if r1 != 0 goto +91 <LBB5_315>
    2723:	r6 = 0
    2724:	*(u32 *)(r9 + 56) = r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2725:	r7 = *(u16 *)(r8 + 6)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2726:	r1 = r9
    2727:	call 34
    2728:	*(u32 *)(r10 - 100) = r0
    2729:	r1 = 269484546
; addr->p2 &= GET_PREFIX(prefix);
    2730:	*(u32 *)(r10 - 104) = r1
; addr->p3 &= GET_PREFIX(prefix);
    2731:	*(u32 *)(r10 - 96) = r7
; addr->p1 &= GET_PREFIX(prefix);
    2732:	r1 = 2
    2733:	*(u32 *)(r10 - 92) = r1
    2734:	*(u32 *)(r10 - 88) = r6
    2735:	r4 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2736:	r4 += -104
; return map_lookup_elem(map, &key);
    2737:	r1 = r9
    2738:	r2 = 0 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2740:	r3 = 4294967295 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2742:	r5 = 20
    2743:	call 25
; addr->p2 &= GET_PREFIX(prefix);
    2744:	r1 = *(u64 *)(r8 + 16)
; addr->p3 &= GET_PREFIX(prefix);
    2745:	*(u64 *)(r10 - 184) = r1
; addr->p1 &= GET_PREFIX(prefix);
    2746:	r1 = *(u64 *)(r8 + 24)
    2747:	*(u64 *)(r10 - 8) = r1
    2748:	r1 = *(u64 *)(r10 - 200)
    2749:	r3 = *(u8 *)(r1 + 22)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2750:	if r3 > 1 goto +89 <LBB5_317>

LBB5_310:
; return map_lookup_elem(map, &key);
    2751:	r7 = 4294967162 ll
    2753:	goto +693 <LBB5_372>

LBB5_311:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2754:	r2 = *(u64 *)(r10 - 312)
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2755:	r1 = r2
    2756:	r1 <<= 32
    2757:	r1 >>= 32
    2758:	if r1 == 0 goto +223 <LBB5_325>
; addr->p2 &= GET_PREFIX(prefix);
    2759:	r8 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2760:	*(u32 *)(r10 - 16) = r8
; addr->p1 &= GET_PREFIX(prefix);
    2761:	*(u64 *)(r10 - 24) = r8
    2762:	*(u64 *)(r10 - 32) = r8
    2763:	r6 = 2
    2764:	*(u32 *)(r10 - 40) = r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2765:	r2 = be32 r2
; return map_lookup_elem(map, &key);
    2766:	*(u32 *)(r10 - 36) = r2
    2767:	r1 = r9
    2768:	r7 = r2
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2769:	call 34
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2770:	*(u32 *)(r10 - 100) = r0
    2771:	r1 = 269484802
    2772:	*(u32 *)(r10 - 104) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2773:	*(u32 *)(r10 - 96) = r7
; addr->p3 &= GET_PREFIX(prefix);
    2774:	*(u32 *)(r10 - 92) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2775:	*(u32 *)(r10 - 88) = r8
    2776:	r4 = r10
    2777:	r4 += -104
    2778:	r1 = r9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2779:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    2781:	r3 = 4294967295 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2783:	r5 = 20
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2784:	call 25
    2785:	r2 = r10
    2786:	r2 += -40
    2787:	r1 = r9
; addr->p2 &= GET_PREFIX(prefix);
    2788:	r3 = 28
; addr->p3 &= GET_PREFIX(prefix);
    2789:	r4 = 0
; addr->p1 &= GET_PREFIX(prefix);
    2790:	call 21
    2791:	r7 = 4294967155 ll
    2793:	r0 <<= 32
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2794:	r0 s>>= 32
; return map_lookup_elem(map, &key);
    2795:	if r0 s< 0 goto +651 <LBB5_372>
    2796:	r6 = *(u32 *)(r9 + 0)
    2797:	*(u64 *)(r10 - 96) = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2798:	*(u64 *)(r10 - 104) = r8
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2799:	r1 = 512
    2800:	*(u64 *)(r10 - 184) = r1
    2801:	r2 = r10
; addr->p2 &= GET_PREFIX(prefix);
    2802:	r2 += -184
; addr->p3 &= GET_PREFIX(prefix);
    2803:	r1 = 0 ll
; addr->p1 &= GET_PREFIX(prefix);
    2805:	call 1
    2806:	if r0 == 0 goto +236 <LBB5_328>
    2807:	r1 = *(u64 *)(r0 + 0)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2808:	r1 += 1
; return map_lookup_elem(map, &key);
    2809:	*(u64 *)(r0 + 0) = r1
    2810:	r1 = *(u64 *)(r0 + 8)
    2811:	r1 += r6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2812:	*(u64 *)(r0 + 8) = r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2813:	goto +240 <LBB5_329>

LBB5_315:
    2814:	r1 = 95142176846542 ll
    2816:	*(u64 *)(r10 - 184) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2817:	r6 = *(u32 *)(r9 + 56)
; addr->p3 &= GET_PREFIX(prefix);
    2818:	r1 = r9
; addr->p1 &= GET_PREFIX(prefix);
    2819:	call 34
    2820:	*(u32 *)(r10 - 100) = r0
    2821:	r1 = 269488898
    2822:	*(u32 *)(r10 - 104) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2823:	*(u32 *)(r10 - 96) = r6
; return map_lookup_elem(map, &key);
    2824:	r1 = 0
    2825:	*(u32 *)(r10 - 92) = r1
    2826:	*(u32 *)(r10 - 88) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2827:	r4 = r10
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2828:	r4 += -104
    2829:	r1 = r9
    2830:	r2 = 0 ll
; addr->p3 &= GET_PREFIX(prefix);
    2832:	r3 = 4294967295 ll
; addr->p1 &= GET_PREFIX(prefix);
    2834:	r5 = 20
    2835:	call 25
    2836:	r1 = *(u64 *)(r10 - 200)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2837:	r3 = *(u8 *)(r1 + 22)
; return map_lookup_elem(map, &key);
    2838:	if r3 > 1 goto +83 <LBB5_321>
    2839:	goto -89 <LBB5_310>

LBB5_317:
    2840:	r1 = r3
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2841:	r1 += 255
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2842:	*(u8 *)(r10 - 104) = r1
    2843:	r4 = r3
    2844:	r4 += -1
    2845:	r4 &= 255
; addr->p2 &= GET_PREFIX(prefix);
    2846:	r1 = r9
; addr->p3 &= GET_PREFIX(prefix);
    2847:	r2 = 24
; addr->p1 &= GET_PREFIX(prefix);
    2848:	r5 = 2
    2849:	call 10
    2850:	r3 = r10
    2851:	r3 += -104
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2852:	r1 = r9
; return map_lookup_elem(map, &key);
    2853:	r2 = 22
    2854:	r4 = 1
    2855:	r5 = 0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2856:	call 9
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2857:	r3 = r10
    2858:	r3 += -8
    2859:	r1 = r9
; addr->p2 &= GET_PREFIX(prefix);
    2860:	r2 = 6
; addr->p3 &= GET_PREFIX(prefix);
    2861:	r4 = 6
; addr->p1 &= GET_PREFIX(prefix);
    2862:	r5 = 0
    2863:	call 9
    2864:	r7 = 4294967155 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2866:	r0 <<= 32
; return map_lookup_elem(map, &key);
    2867:	r0 s>>= 32
    2868:	if r0 s< 0 goto +578 <LBB5_372>
    2869:	r3 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2870:	r3 += -184
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2871:	r6 = 0
    2872:	r1 = r9
    2873:	r2 = 0
    2874:	r4 = 6
; addr->p2 &= GET_PREFIX(prefix);
    2875:	r5 = 0
; addr->p3 &= GET_PREFIX(prefix);
    2876:	call 9
; addr->p1 &= GET_PREFIX(prefix);
    2877:	r7 = r0
    2878:	r7 <<= 32
    2879:	r7 s>>= 63
    2880:	r7 &= -141
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2881:	if r7 != 0 goto +565 <LBB5_372>
; return map_lookup_elem(map, &key);
    2882:	r7 = *(u32 *)(r8 + 0)
    2883:	r1 = r9
    2884:	call 34
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2885:	*(u32 *)(r10 - 100) = r0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2886:	r1 = 269485058
    2887:	*(u32 *)(r10 - 104) = r1
    2888:	*(u32 *)(r10 - 96) = r7
; addr->p2 &= GET_PREFIX(prefix);
    2889:	*(u32 *)(r10 - 92) = r6
; addr->p3 &= GET_PREFIX(prefix);
    2890:	*(u32 *)(r10 - 88) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2891:	r4 = r10
    2892:	r4 += -104
    2893:	r1 = r9
    2894:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    2896:	r3 = 4294967295 ll
    2898:	r5 = 20
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2899:	call 25
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2900:	r1 = 2
    2901:	*(u32 *)(r9 + 48) = r1
    2902:	r1 = *(u32 *)(r8 + 0)
    2903:	*(u32 *)(r9 + 52) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2904:	r7 = *(u32 *)(r9 + 0)
; addr->p3 &= GET_PREFIX(prefix);
    2905:	*(u64 *)(r10 - 96) = r6
; addr->p1 &= GET_PREFIX(prefix);
    2906:	*(u64 *)(r10 - 104) = r6
    2907:	r1 = 512
    2908:	*(u64 *)(r10 - 40) = r1
    2909:	r2 = r10
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2910:	r2 += -40
; return map_lookup_elem(map, &key);
    2911:	r1 = 0 ll
    2913:	call 1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2914:	if r0 == 0 goto +387 <LBB5_356>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2915:	r1 = *(u64 *)(r0 + 0)
    2916:	r1 += 1
    2917:	*(u64 *)(r0 + 0) = r1
; addr->p2 &= GET_PREFIX(prefix);
    2918:	r1 = *(u64 *)(r0 + 8)
; addr->p3 &= GET_PREFIX(prefix);
    2919:	r1 += r7
; addr->p1 &= GET_PREFIX(prefix);
    2920:	*(u64 *)(r0 + 8) = r1
    2921:	goto +391 <LBB5_357>

LBB5_321:
    2922:	r1 = r3
    2923:	r1 += 255
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2924:	*(u8 *)(r10 - 104) = r1
; return map_lookup_elem(map, &key);
    2925:	r4 = r3
    2926:	r4 += -1
    2927:	r4 &= 255
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2928:	r1 = r9
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2929:	r2 = 24
    2930:	r5 = 2
    2931:	call 10
    2932:	r3 = r10
; addr->p2 &= GET_PREFIX(prefix);
    2933:	r3 += -104
; addr->p3 &= GET_PREFIX(prefix);
    2934:	r1 = r9
; addr->p1 &= GET_PREFIX(prefix);
    2935:	r2 = 22
    2936:	r4 = 1
    2937:	r5 = 0
    2938:	call 9
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2939:	r3 = r10
; return map_lookup_elem(map, &key);
    2940:	r3 += -128
    2941:	r1 = r9
    2942:	r2 = 6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2943:	r4 = 6
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    2944:	r5 = 0
    2945:	call 9
    2946:	r7 = 4294967155 ll
; addr->p3 &= GET_PREFIX(prefix);
    2948:	r0 <<= 32
    2949:	r0 s>>= 32
; addr->p1 &= GET_PREFIX(prefix);
    2950:	if r0 s< 0 goto +496 <LBB5_372>
    2951:	r3 = r10
    2952:	r3 += -184
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2953:	r8 = 0
; return map_lookup_elem(map, &key);
    2954:	r1 = r9
    2955:	r2 = 0
    2956:	r4 = 6
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    2957:	r5 = 0
; if (info != NULL && info->sec_label) {
    2958:	call 9
    2959:	r7 = r0
    2960:	r7 <<= 32
    2961:	r7 s>>= 63
; *dstID = WORLD_ID;
    2962:	r7 &= -141
    2963:	if r7 != 0 goto +483 <LBB5_372>
    2964:	r6 = *(u32 *)(r9 + 0)
    2965:	*(u64 *)(r10 - 96) = r8
    2966:	*(u64 *)(r10 - 104) = r8
    2967:	r1 = 512
; *dstID = info->sec_label;
    2968:	*(u64 *)(r10 - 40) = r1
    2969:	r2 = r10
    2970:	r2 += -40
; tunnel_endpoint = info->tunnel_endpoint;
    2971:	r1 = 0 ll
    2973:	call 1
; uint32_t hash = get_hash_recalc(skb);
    2974:	if r0 == 0 goto +346 <LBB5_358>
    2975:	r1 = *(u64 *)(r0 + 0)
; struct debug_msg msg = {
    2976:	r1 += 1
    2977:	*(u64 *)(r0 + 0) = r1
    2978:	r1 = *(u64 *)(r0 + 8)
    2979:	r1 += r6
    2980:	*(u64 *)(r0 + 8) = r1
    2981:	goto +350 <LBB5_359>

LBB5_325:
    2982:	r8 = 0
    2983:	*(u32 *)(r10 - 168) = r8
    2984:	*(u32 *)(r10 - 172) = r8
    2985:	*(u32 *)(r10 - 176) = r8
    2986:	*(u32 *)(r10 - 180) = r8
    2987:	r1 = 1
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    2988:	*(u8 *)(r10 - 168) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    2989:	r6 &= 65535
    2990:	*(u32 *)(r10 - 184) = r6
    2991:	r2 = r10
    2992:	r2 += -184
    2993:	r1 = 0 ll
    2995:	call 1
; verdict = policy_can_egress6(skb, tuple, *dstID,
    2996:	if r0 == 0 goto +163 <LBB5_342>
    2997:	r1 = *(u8 *)(r0 + 1)
; return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
    2998:	r1 <<= 8
    2999:	r2 = *(u8 *)(r0 + 0)
    3000:	r1 |= r2
    3001:	r2 = *(u8 *)(r0 + 2)
    3002:	r6 = *(u8 *)(r0 + 3)
; struct policy_key key = {
    3003:	r6 <<= 8
    3004:	r6 |= r2
; return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
    3005:	r6 <<= 16
    3006:	r6 |= r1
; struct policy_key key = {
    3007:	*(u32 *)(r10 - 16) = r8
    3008:	*(u64 *)(r10 - 24) = r8
    3009:	*(u64 *)(r10 - 32) = r8
    3010:	r7 = 2
    3011:	*(u32 *)(r10 - 40) = r7
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3012:	r6 = be32 r6
; policy = map_lookup_elem(map, &key);
    3013:	*(u32 *)(r10 - 36) = r6
    3014:	r1 = r9
    3015:	call 34
    3016:	*(u32 *)(r10 - 100) = r0
; if (likely(policy)) {
    3017:	r1 = 269484802
    3018:	*(u32 *)(r10 - 104) = r1
; uint32_t hash = get_hash_recalc(skb);
    3019:	*(u32 *)(r10 - 96) = r6
    3020:	*(u32 *)(r10 - 92) = r7
; struct debug_msg msg = {
    3021:	*(u32 *)(r10 - 88) = r8
    3022:	r4 = r10
    3023:	r4 += -104
    3024:	r1 = r9
    3025:	r2 = 0 ll
; dport << 16 | proto);
    3027:	r3 = 4294967295 ll
    3029:	r5 = 20
; struct debug_msg msg = {
    3030:	call 25
    3031:	r2 = r10
; static inline void cilium_dbg3(struct __sk_buff *skb, __u8 type, __u32 arg1,
    3032:	r2 += -40
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3033:	r1 = r9
    3034:	r3 = 28
    3035:	r4 = 0
    3036:	call 21
    3037:	r0 <<= 32
    3038:	r0 s>>= 32
    3039:	if r0 s> -1 goto +47 <LBB5_333>
; __sync_fetch_and_add(&policy->packets, 1);
    3040:	r7 = 4294967155 ll
; __sync_fetch_and_add(&policy->bytes, skb->len);
    3042:	goto +404 <LBB5_372>

LBB5_328:
    3043:	*(u64 *)(r10 - 96) = r6
    3044:	r1 = 1
; return policy->proxy_port;
    3045:	*(u64 *)(r10 - 104) = r1
    3046:	r2 = r10
    3047:	r2 += -184
    3048:	r3 = r10
    3049:	r3 += -104
; switch (ret) {
    3050:	r1 = 0 ll
    3052:	r4 = 0
    3053:	call 2

LBB5_329:
    3054:	r2 = *(u64 *)(r10 - 304)
    3055:	r2 <<= 32
    3056:	r2 >>= 32
; if (tuple->nexthdr == IPPROTO_TCP) {
    3057:	if r2 == 0 goto +385 <LBB5_371>
    3058:	r6 = *(u32 *)(r9 + 0)
; struct ct_entry entry = { };
    3059:	r1 = r9
    3060:	r7 = r2
    3061:	call 34
    3062:	r3 = r7
    3063:	r1 = 0
    3064:	*(u32 *)(r10 - 80) = r1
    3065:	*(u32 *)(r10 - 100) = r0
    3066:	r1 = 269485060
; entry.rev_nat_index = ct_state->rev_nat_index;
    3067:	*(u32 *)(r10 - 104) = r1
; entry.slave = ct_state->slave;
    3068:	r1 = 2
    3069:	*(u64 *)(r10 - 88) = r1
; ret = ct_create6(get_ct_map6(tuple), tuple, skb, CT_EGRESS, &ct_state_new);
    3070:	r1 = 1
    3071:	*(u32 *)(r10 - 76) = r1
    3072:	*(u32 *)(r10 - 96) = r6
    3073:	if r3 < r6 goto +1 <LBB5_332>
    3074:	r3 = r6

LBB5_332:
    3075:	*(u32 *)(r10 - 92) = r3
    3076:	r3 <<= 32
; entry.lb_loopback = ct_state->loopback;
    3077:	r1 = 4294967295 ll
; if (tcp) {
    3079:	r3 |= r1
; entry->seen_non_syn |= !syn;
    3080:	r4 = r10
; return ktime_get_ns();
    3081:	r4 += -104
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3082:	r1 = r9
; entry->lifetime = now + lifetime;
    3083:	r2 = 0 ll
    3085:	r5 = 32
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3086:	goto +355 <LBB5_370>

LBB5_333:
    3087:	r6 = *(u32 *)(r9 + 0)
    3088:	r1 = 0
; if (*last_report + CT_REPORT_INTERVAL < now ||
    3089:	*(u64 *)(r10 - 96) = r1
    3090:	*(u64 *)(r10 - 104) = r1
    3091:	r1 = 512
    3092:	*(u64 *)(r10 - 8) = r1
    3093:	r2 = r10
; *last_report = now;
    3094:	r2 += -8
    3095:	r1 = 0 ll
; entry.tx_packets = 1;
    3097:	call 1
; entry.tx_bytes = skb->len;
    3098:	if r0 == 0 goto +7 <LBB5_335>
    3099:	r1 = *(u64 *)(r0 + 0)
; uint32_t hash = get_hash_recalc(skb);
    3100:	r1 += 1
    3101:	*(u64 *)(r0 + 0) = r1
; struct debug_msg msg = {
    3102:	r1 = *(u64 *)(r0 + 8)
    3103:	r1 += r6
    3104:	*(u64 *)(r0 + 8) = r1
; cilium_dbg3(skb, DBG_CT_CREATED6, entry.rev_nat_index, ct_state->src_sec_id, 0);
    3105:	goto +11 <LBB5_336>

LBB5_335:
; struct debug_msg msg = {
    3106:	*(u64 *)(r10 - 96) = r6
    3107:	r1 = 1
    3108:	*(u64 *)(r10 - 104) = r1
    3109:	r2 = r10
    3110:	r2 += -8
    3111:	r3 = r10
; entry.tx_packets = 1;
    3112:	r3 += -104
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3113:	r1 = 0 ll
    3115:	r4 = 0
    3116:	call 2

LBB5_336:
    3117:	r7 = *(u64 *)(r10 - 304)
    3118:	r7 <<= 32
    3119:	r7 >>= 32
; entry.src_sec_id = ct_state->src_sec_id;
    3120:	if r7 == 0 goto +28 <LBB5_340>
    3121:	r6 = *(u32 *)(r9 + 0)
; entry.tx_packets = 1;
    3122:	r1 = r9
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    3123:	call 34
    3124:	r1 = 0
    3125:	*(u32 *)(r10 - 80) = r1
    3126:	*(u32 *)(r10 - 100) = r0
    3127:	r1 = 269485060
    3128:	*(u32 *)(r10 - 104) = r1
    3129:	r1 = 2
    3130:	*(u64 *)(r10 - 88) = r1
    3131:	r1 = 1
    3132:	*(u32 *)(r10 - 76) = r1
    3133:	*(u32 *)(r10 - 96) = r6
    3134:	if r7 < r6 goto +1 <LBB5_339>
; skb->cb[CB_POLICY] = 1;
    3135:	r7 = r6

LBB5_339:
    3136:	*(u32 *)(r10 - 92) = r7
    3137:	r7 <<= 32
; if (ct_state.rev_nat_index) {
    3138:	r1 = 4294967295 ll
    3140:	r7 |= r1
    3141:	r4 = r10
    3142:	r4 += -104
; uint32_t hash = get_hash_recalc(skb);
    3143:	r1 = r9
    3144:	r2 = 0 ll
; struct debug_msg msg = {
    3146:	r3 = r7
    3147:	r5 = 32
    3148:	call 25

LBB5_340:
    3149:	r1 = 1
    3150:	r2 = 0
    3151:	call 23
    3152:	r7 = r0
    3153:	r1 = r7
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3154:	r1 <<= 32
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3155:	r1 >>= 32
    3156:	r2 = 4294967136 ll
    3158:	if r1 == r2 goto +1 <LBB5_342>
    3159:	goto +287 <LBB5_372>

LBB5_342:
    3160:	r1 = r9
    3161:	call 34
    3162:	*(u32 *)(r10 - 100) = r0
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    3163:	r1 = 269489154
; nat = map_lookup_elem(&cilium_lb6_reverse_nat, &index);
    3164:	*(u32 *)(r10 - 104) = r1
    3165:	*(u64 *)(r10 - 96) = r8
    3166:	*(u32 *)(r10 - 88) = r8
    3167:	r4 = r10
; if (nat == NULL)
    3168:	r4 += -104
; cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);
    3169:	r1 = r9
    3170:	r2 = 0 ll
    3172:	r3 = 4294967295 ll
    3174:	r5 = 20
    3175:	call 25
    3176:	r1 = *(u64 *)(r10 - 200)
    3177:	r3 = *(u8 *)(r1 + 22)
    3178:	if r3 > 1 goto +1 <LBB5_344>
    3179:	goto -429 <LBB5_310>

LBB5_344:
; uint32_t hash = get_hash_recalc(skb);
    3180:	r1 = r3
    3181:	r1 += 255
; struct debug_msg msg = {
    3182:	*(u8 *)(r10 - 104) = r1
    3183:	r4 = r3
    3184:	r4 += -1
    3185:	r4 &= 255
    3186:	r1 = r9
    3187:	r2 = 24
; cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);
    3188:	r5 = 2
    3189:	call 10
    3190:	r3 = r10
    3191:	r3 += -104
    3192:	r6 = 0
    3193:	r1 = r9
    3194:	r2 = 22
    3195:	r4 = 1
    3196:	r5 = 0
; struct debug_msg msg = {
    3197:	call 9
    3198:	r3 = r10
; struct ipv6_ct_tuple *tuple, int flags,
    3199:	r3 += -128
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3200:	r1 = r9
    3201:	r2 = 0
    3202:	r4 = 6
    3203:	r5 = 0
    3204:	call 9
    3205:	r7 = r0
; if (nat->port) {
    3206:	r7 <<= 32
    3207:	r7 s>>= 63
    3208:	r7 &= -141
    3209:	r4 = *(u64 *)(r10 - 208)
    3210:	r8 = *(u64 *)(r10 - 264)
    3211:	if r7 != 0 goto +236 <LBB5_373>
    3212:	r7 = *(u32 *)(r9 + 0)
    3213:	*(u64 *)(r10 - 96) = r6
    3214:	*(u64 *)(r10 - 104) = r6
    3215:	r1 = 512
; switch (nexthdr) {
    3216:	*(u64 *)(r10 - 40) = r1
    3217:	r2 = r10
    3218:	r2 += -40
    3219:	r1 = 0 ll
; struct ipv6_ct_tuple icmp_tuple = {
    3221:	call 1
    3222:	if r0 == 0 goto +7 <LBB5_347>
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    3223:	r1 = *(u64 *)(r0 + 0)
    3224:	r1 += 1
; .flags = tuple->flags | TUPLE_F_RELATED,
    3225:	*(u64 *)(r0 + 0) = r1
; entry.seen_non_syn = true; /* For ICMP, there is no SYN. */
    3226:	r1 = *(u64 *)(r0 + 8)
; .flags = tuple->flags | TUPLE_F_RELATED,
    3227:	r1 += r7
; struct ipv6_ct_tuple icmp_tuple = {
    3228:	*(u64 *)(r0 + 8) = r1
; dst->p1 = src->p1;
    3229:	goto +11 <LBB5_348>

LBB5_347:
    3230:	*(u64 *)(r10 - 96) = r7
; dst->p2 = src->p2;
    3231:	r1 = 1
    3232:	*(u64 *)(r10 - 104) = r1
; dst->p3 = src->p3;
    3233:	r2 = r10
    3234:	r2 += -40
; dst->p4 = src->p4;
    3235:	r3 = r10
    3236:	r3 += -104
; dst->p1 = src->p1;
    3237:	r1 = 0 ll
; dst->p2 = src->p2;
    3239:	r4 = 0
    3240:	call 2

LBB5_348:
; dst->p3 = src->p3;
    3241:	r2 = *(u64 *)(r10 - 304)
    3242:	r2 <<= 32
; dst->p4 = src->p4;
    3243:	r2 >>= 32
    3244:	if r2 == 0 goto +32 <LBB5_352>
    3245:	r6 = *(u32 *)(r9 + 0)
; struct ipv6_ct_tuple icmp_tuple = {
    3246:	r1 = r9
    3247:	r7 = r2
    3248:	call 34
; if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
    3249:	r3 = r7
    3250:	*(u32 *)(r10 - 100) = r0
    3251:	r1 = 269484804
    3252:	*(u32 *)(r10 - 104) = r1
    3253:	r1 = 2
    3254:	*(u32 *)(r10 - 88) = r1
; return DROP_CT_CREATE_FAILED;
    3255:	r1 = *(u64 *)(r10 - 208)
    3256:	*(u32 *)(r10 - 84) = r1
    3257:	*(u8 *)(r10 - 78) = r8
; if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
    3258:	r1 = 0
    3259:	*(u16 *)(r10 - 80) = r1
    3260:	*(u8 *)(r10 - 77) = r1
    3261:	*(u32 *)(r10 - 76) = r1
; if (IS_ERR(ret))
    3262:	*(u32 *)(r10 - 96) = r6
    3263:	if r3 < r6 goto +1 <LBB5_351>
; return verdict > 0 && (dir == CT_NEW || dir == CT_ESTABLISHED);
    3264:	r3 = r6

LBB5_351:
    3265:	*(u32 *)(r10 - 92) = r3
    3266:	r3 <<= 32
; if (redirect_to_proxy(verdict, forwarding_reason)) {
    3267:	r1 = 4294967295 ll
; union macaddr host_mac = HOST_IFINDEX_MAC;
    3269:	r3 |= r1
    3270:	r4 = r10
; BPF_V6(host_ip, HOST_IP);
    3271:	r4 += -104
    3272:	r1 = r9
    3273:	r2 = 0 ll
    3275:	r5 = 32
; verdict, tuple->dport,
    3276:	call 25

LBB5_352:
    3277:	r8 = *(u32 *)(r9 + 0)
    3278:	r1 = r9
    3279:	call 34
    3280:	*(u32 *)(r10 - 100) = r0
    3281:	r1 = 269485059
    3282:	*(u32 *)(r10 - 104) = r1
    3283:	*(u32 *)(r10 - 96) = r8
; .saddr = tuple->daddr,
    3284:	if r8 < 128 goto +1 <LBB5_354>
    3285:	r8 = 128

LBB5_354:
    3286:	*(u32 *)(r10 - 92) = r8
    3287:	r8 <<= 32
    3288:	r1 = 4294967295 ll
    3290:	r8 |= r1
    3291:	r7 = 0
    3292:	*(u64 *)(r10 - 88) = r7
    3293:	r4 = r10
    3294:	r4 += -104
    3295:	r1 = r9
    3296:	r2 = 0 ll
    3298:	r3 = r8
    3299:	r5 = 24

LBB5_355:
    3300:	call 25
    3301:	goto +145 <LBB5_372>

LBB5_356:
    3302:	*(u64 *)(r10 - 96) = r7
    3303:	r1 = 1
    3304:	*(u64 *)(r10 - 104) = r1
    3305:	r2 = r10
    3306:	r2 += -40
    3307:	r3 = r10
    3308:	r3 += -104
    3309:	r1 = 0 ll
    3311:	r4 = 0
    3312:	call 2

LBB5_357:
    3313:	r3 = *(u16 *)(r8 + 6)
    3314:	r1 = r9
    3315:	r2 = 0 ll
    3317:	call 12
    3318:	r7 = 4294967156 ll
; struct proxy6_tbl_key key = {
    3320:	goto +126 <LBB5_372>

LBB5_358:
; verdict, tuple->dport,
    3321:	*(u64 *)(r10 - 96) = r6
    3322:	r1 = 1
    3323:	*(u64 *)(r10 - 104) = r1
; .saddr = tuple->daddr,
    3324:	r2 = r10
    3325:	r2 += -40
    3326:	r3 = r10
    3327:	r3 += -104
    3328:	r1 = 0 ll
    3330:	r4 = 0
    3331:	call 2

LBB5_359:
    3332:	r7 = *(u64 *)(r10 - 264)
    3333:	r2 = *(u64 *)(r10 - 304)
    3334:	r2 <<= 32
    3335:	r2 >>= 32
    3336:	if r2 == 0 goto +32 <LBB5_363>
    3337:	r6 = *(u32 *)(r9 + 0)
    3338:	r1 = r9
; .sport = tuple->sport,
    3339:	r8 = r2
    3340:	call 34
    3341:	r3 = r8
    3342:	*(u32 *)(r10 - 100) = r0
; struct proxy6_tbl_key key = {
    3343:	r1 = 269484548
; .nexthdr = tuple->nexthdr,
    3344:	*(u32 *)(r10 - 104) = r1
; struct proxy6_tbl_key key = {
    3345:	r1 = 4294967298 ll
    3347:	*(u64 *)(r10 - 88) = r1
; struct proxy6_tbl_value value = {
    3348:	*(u8 *)(r10 - 78) = r7
    3349:	r1 = 0
    3350:	*(u16 *)(r10 - 80) = r1
; .orig_daddr = old_ip,
    3351:	*(u8 *)(r10 - 77) = r1
    3352:	r1 = 1
    3353:	*(u32 *)(r10 - 76) = r1
    3354:	*(u32 *)(r10 - 96) = r6
; struct proxy6_tbl_value value = {
    3355:	if r3 < r6 goto +1 <LBB5_362>
; return ktime_get_ns();
    3356:	r3 = r6

LBB5_362:
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    3357:	*(u32 *)(r10 - 92) = r3
; value->lifetime = bpf_ktime_get_sec() + PROXY_DEFAULT_LIFETIME;
    3358:	r3 <<= 32
    3359:	r1 = 4294967295 ll
; if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
    3361:	r3 |= r1
    3362:	r4 = r10
; switch (obs_point) {
    3363:	r4 += -104
    3364:	r1 = r9
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3365:	r2 = 0 ll
; struct trace_notify msg = {
    3367:	r5 = 32
    3368:	call 25

LBB5_363:
    3369:	r7 = *(u32 *)(r9 + 0)
    3370:	r1 = r9
    3371:	call 34
    3372:	*(u32 *)(r10 - 100) = r0
    3373:	r1 = 269485059
    3374:	*(u32 *)(r10 - 104) = r1
    3375:	*(u32 *)(r10 - 96) = r7
    3376:	if r7 < 128 goto +51 <LBB5_369>
    3377:	goto +49 <LBB5_368>

LBB5_365:
    3378:	r1 = r3
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3379:	r1 += 255
    3380:	*(u8 *)(r10 - 104) = r1
; struct trace_notify msg = {
    3381:	r4 = r3
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    3382:	r4 += -1
    3383:	r4 &= 255
    3384:	r1 = r9
    3385:	r2 = 24
    3386:	r5 = 2
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)monitor, (uint64_t)skb_len);
    3387:	call 10
; skb_event_output(skb, &cilium_events,
    3388:	r3 = r10
    3389:	r3 += -104
    3390:	r1 = r9
    3391:	r2 = 22
    3392:	r4 = 1
    3393:	r5 = 0
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3394:	call 9
    3395:	r3 = r10
    3396:	r3 += -128
    3397:	r1 = r9
    3398:	r2 = 6
    3399:	r4 = 6
    3400:	r5 = 0
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    3401:	call 9
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3402:	r7 = 4294967155 ll
    3404:	r0 <<= 32
    3405:	r0 s>>= 32
    3406:	if r0 s< 0 goto +40 <LBB5_372>
    3407:	r3 = r10
    3408:	r3 += -8
    3409:	r1 = r9
    3410:	r2 = 0
    3411:	r4 = 6
    3412:	r5 = 0
; if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    3413:	call 9
    3414:	r7 = r0
    3415:	r7 <<= 32
    3416:	r7 s>>= 63
    3417:	r7 &= -141
    3418:	if r7 != 0 goto +28 <LBB5_372>
; if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
    3419:	r7 = *(u32 *)(r9 + 0)
    3420:	r1 = r9
    3421:	call 34
    3422:	*(u32 *)(r10 - 100) = r0
    3423:	r1 = 269485059
    3424:	*(u32 *)(r10 - 104) = r1
    3425:	*(u32 *)(r10 - 96) = r7
    3426:	if r7 < 128 goto +1 <LBB5_369>

LBB5_368:
    3427:	r7 = 128

LBB5_369:
    3428:	*(u32 *)(r10 - 92) = r7
    3429:	r7 <<= 32
    3430:	r1 = 4294967295 ll
    3432:	r7 |= r1
; static inline int ipv6_store_daddr(struct __sk_buff *skb, __u8 *addr, int off)
    3433:	r1 = 1
; return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
    3434:	*(u64 *)(r10 - 88) = r1
    3435:	r4 = r10
    3436:	r4 += -104
    3437:	r1 = r9
    3438:	r2 = 0 ll
    3440:	r3 = r7
; if (ipv6_store_daddr(skb, host_ip->addr, ETH_HLEN) > 0)
    3441:	r5 = 24

LBB5_370:
; if (csum->offset) {
    3442:	call 25

LBB5_371:
    3443:	r1 = 1
    3444:	r2 = 0
; __be32 sum = csum_diff(old_ip.addr, 16, host_ip->addr, 16, 0);
    3445:	call 23
    3446:	r7 = r0

LBB5_372:
    3447:	r4 = *(u64 *)(r10 - 208)

LBB5_373:
    3448:	r1 = r7
    3449:	r1 <<= 32
    3450:	r1 >>= 32
    3451:	r2 = 1
    3452:	if r1 == 2 goto +1 <LBB5_375>
; return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
    3453:	r2 = 0

LBB5_375:
    3454:	r1 >>= 31
    3455:	r1 |= r2
    3456:	if r1 == 0 goto +46 <LBB5_380>
    3457:	r1 = 2
    3458:	*(u32 *)(r9 + 48) = r1
    3459:	r4 &= 65535
    3460:	r4 |= 131072
    3461:	*(u32 *)(r9 + 52) = r4
    3462:	*(u32 *)(r9 + 56) = r7
    3463:	r1 = 0
    3464:	*(u32 *)(r9 + 60) = r1
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3465:	*(u32 *)(r9 + 64) = r1
; uint32_t hash = get_hash_recalc(skb);
    3466:	r6 = *(u32 *)(r9 + 0)
    3467:	*(u64 *)(r10 - 96) = r1
; struct debug_capture_msg msg = {
    3468:	*(u64 *)(r10 - 104) = r1
    3469:	r1 = 512
    3470:	*(u64 *)(r10 - 40) = r1
    3471:	r7 = -r7
    3472:	*(u8 *)(r10 - 40) = r7
    3473:	r2 = r10
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3474:	r2 += -40
    3475:	r1 = 0 ll
; (cap_len << 32) | BPF_F_CURRENT_CPU,
    3477:	call 1
    3478:	if r0 == 0 goto +7 <LBB5_378>
    3479:	r1 = *(u64 *)(r0 + 0)
    3480:	r1 += 1
    3481:	*(u64 *)(r0 + 0) = r1
; struct debug_capture_msg msg = {
    3482:	r1 = *(u64 *)(r0 + 8)
    3483:	r1 += r6
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3484:	*(u64 *)(r0 + 8) = r1
    3485:	goto +11 <LBB5_379>

LBB5_378:
; skb_event_output(skb, &cilium_events,
    3486:	*(u64 *)(r10 - 96) = r6
    3487:	r1 = 1
    3488:	*(u64 *)(r10 - 104) = r1
    3489:	r2 = r10
    3490:	r2 += -40
    3491:	r3 = r10
    3492:	r3 += -104
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3493:	r1 = 0 ll
    3495:	r4 = 0
; if (map_update_elem(&cilium_proxy6, &key, &value, 0) < 0)
    3496:	call 2

LBB5_379:
    3497:	r1 = r9
    3498:	r2 = 0 ll
    3500:	r3 = 1
    3501:	call 12
; return DROP_PROXYMAP_CREATE_FAILED;
    3502:	r7 = 2

LBB5_380:
    3503:	r0 = r7
; if (IS_ERR(ret))
    3504:	exit

LBB5_381:
    3505:	r7 = *(u64 *)(r10 - 280)
    3506:	r1 = 0
    3507:	*(u8 *)(r10 - 34) = r1
    3508:	*(u16 *)(r10 - 36) = r1
    3509:	r2 = r10
    3510:	r2 += -40
    3511:	r1 = 0 ll
; cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);
    3513:	call 1
; uint32_t hash = get_hash_recalc(skb);
    3514:	if r0 == 0 goto +7 <LBB5_383>
    3515:	r1 = 1
; struct debug_msg msg = {
    3516:	lock *(u64 *)(r0 + 8) += r1
    3517:	r9 = *(u64 *)(r10 - 192)
    3518:	r1 = *(u32 *)(r9 + 0)
    3519:	lock *(u64 *)(r0 + 16) += r1
    3520:	r3 = 0
    3521:	goto -1552 <LBB5_216>

LBB5_383:
    3522:	*(u16 *)(r10 - 36) = r9
    3523:	r1 = 0
; cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);
    3524:	*(u32 *)(r10 - 40) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    3525:	*(u8 *)(r10 - 34) = r7
    3526:	r2 = r10
    3527:	r2 += -40
    3528:	r1 = 0 ll
    3530:	call 1
    3531:	r7 = r0
    3532:	if r7 == 0 goto +6 <LBB5_385>
; hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
    3533:	r1 = 1
    3534:	lock *(u64 *)(r7 + 8) += r1
; if (hoplimit <= 1) {
    3535:	r9 = *(u64 *)(r10 - 192)
    3536:	r1 = *(u32 *)(r9 + 0)
    3537:	lock *(u64 *)(r7 + 16) += r1
    3538:	goto -1570 <LBB5_215>

LBB5_385:
; new_hl = hoplimit - 1;
    3539:	r9 = *(u64 *)(r10 - 192)
    3540:	r1 = *(u32 *)(r9 + 56)
    3541:	r4 = *(u64 *)(r10 - 208)
    3542:	r6 = *(u64 *)(r10 - 264)
; if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
    3543:	r8 = *(u64 *)(r10 - 248)
    3544:	r3 = 0
    3545:	if r1 == 0 goto +1 <LBB5_386>
    3546:	goto -1574 <LBB5_217>

LBB5_386:
    3547:	r1 = r9
    3548:	call 34
    3549:	*(u32 *)(r10 - 100) = r0
; return DROP_WRITE_ERROR;
    3550:	r1 = 269485314
    3551:	*(u32 *)(r10 - 104) = r1
; if (IS_ERR(ret))
    3552:	r1 = 2
    3553:	*(u32 *)(r10 - 96) = r1
    3554:	r1 = *(u64 *)(r10 - 208)
    3555:	*(u32 *)(r10 - 92) = r1
    3556:	r1 = 0
    3557:	*(u32 *)(r10 - 88) = r1
    3558:	r4 = r10
    3559:	r4 += -104
    3560:	r1 = r9
; if (ret > 0) {
    3561:	r2 = 0 ll
; skb->cb[1] = direction;
    3563:	r3 = 4294967295 ll
; skb->cb[0] = nh_off;
    3565:	r5 = 20
; tail_call(skb, &CALLS_MAP, index);
    3566:	call 25
    3567:	r4 = *(u64 *)(r10 - 208)
    3568:	r3 = 4294967163 ll
; return skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
    3570:	r1 = r6
    3571:	r1 |= 1
    3572:	if r1 == 3 goto -1600 <LBB5_217>
    3573:	r7 = 4294967163 ll
    3575:	if r6 != 1 goto -128 <LBB5_373>
    3576:	r1 = 0 ll
    3578:	r2 = *(u8 *)(r10 - 108)
; if (smac && eth_store_saddr(skb, smac, 0) < 0)
    3579:	if r2 == 6 goto +2 <LBB5_390>
    3580:	r1 = 0 ll

LBB5_390:
; return skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
    3582:	r2 = r10
    3583:	r2 += -120
    3584:	call 3
    3585:	r8 = r0
    3586:	r8 <<= 32
    3587:	r8 s>>= 32
    3588:	r9 = *(u64 *)(r10 - 192)
; return DROP_WRITE_ERROR;
    3589:	r4 = *(u64 *)(r10 - 208)
    3590:	if r8 s> -1 goto -143 <LBB5_373>
; if (ret != TC_ACT_OK)
    3591:	r1 = r9
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3592:	call 34
; uint32_t hash = get_hash_recalc(skb);
    3593:	*(u32 *)(r10 - 100) = r0
    3594:	r1 = 269488642
; struct debug_capture_msg msg = {
    3595:	*(u32 *)(r10 - 104) = r1
    3596:	r1 = 3
    3597:	*(u32 *)(r10 - 96) = r1
    3598:	*(u32 *)(r10 - 92) = r8
; uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
    3599:	r1 = 0
    3600:	*(u32 *)(r10 - 88) = r1
    3601:	r4 = r10
; switch (nexthdr) {
    3602:	r4 += -104
    3603:	r1 = r9
    3604:	r2 = 0 ll
; return skb_load_bytes(skb, off, port, sizeof(__be16));
    3606:	r3 = 4294967295 ll
    3608:	r5 = 20
    3609:	goto -310 <LBB5_355>
Disassembly of section 2/6:
tail_handle_arp:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 244920237338078 ll
       3:	*(u64 *)(r10 - 48) = r1
       4:	r0 = 0
; struct lb6_key key = {};
       5:	r2 = *(u32 *)(r6 + 80)
       6:	r1 = *(u32 *)(r6 + 76)
       7:	r3 = r1
       8:	r3 += 42
       9:	if r3 > r2 goto +169 <LBB6_22>
; tmp = a->p1 - b->p1;
      10:	r2 = *(u16 *)(r1 + 20)
; if (!tmp)
      11:	if r2 != 256 goto +167 <LBB6_22>
      12:	r2 = *(u16 *)(r1 + 14)
      13:	if r2 != 256 goto +165 <LBB6_22>
; tmp = a->p2 - b->p2;
      14:	r2 = *(u32 *)(r1 + 0)
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r3 = 4022250974 ll
      17:	if r2 == r3 goto +6 <LBB6_6>
; tmp = a->p1 - b->p1;
      18:	r3 = 4294967295 ll
; if (!tmp)
      20:	if r2 != r3 goto +158 <LBB6_22>
      21:	r2 = *(u16 *)(r1 + 4)
; tmp = a->p2 - b->p2;
      22:	if r2 == 65535 goto +3 <LBB6_7>
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	goto +155 <LBB6_22>

LBB6_6:
      24:	r2 = *(u16 *)(r1 + 4)
      25:	if r2 != 57024 goto +153 <LBB6_22>

LBB6_7:
; tmp = a->p1 - b->p1;
      26:	r2 = *(u8 *)(r1 + 39)
; if (!tmp) {
      27:	r2 <<= 8
; tmp = a->p2 - b->p2;
      28:	r3 = *(u8 *)(r1 + 38)
; if (!tmp) {
      29:	r2 |= r3
; tmp = a->p3 - b->p3;
      30:	r3 = *(u8 *)(r1 + 41)
; if (!tmp)
      31:	r3 <<= 8
; tmp = a->p4 - b->p4;
      32:	r4 = *(u8 *)(r1 + 40)
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r3 |= r4
      34:	r3 <<= 16
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r3 |= r2
      36:	*(u32 *)(r10 - 40) = r3
; dst->p1 = src->p1;
      37:	r3 = *(u8 *)(r1 + 7)
      38:	r3 <<= 8
; dst->p2 = src->p2;
      39:	r2 = *(u8 *)(r1 + 6)
      40:	r3 |= r2
; dst->p3 = src->p3;
      41:	r2 = *(u8 *)(r1 + 9)
      42:	r2 <<= 8
; dst->p4 = src->p4;
      43:	r4 = *(u8 *)(r1 + 8)
      44:	r2 |= r4
; dst->p1 = src->p1;
      45:	r2 <<= 16
      46:	r2 |= r3
; dst->p2 = src->p2;
      47:	r3 = *(u8 *)(r1 + 11)
      48:	r3 <<= 8
; dst->p3 = src->p3;
      49:	r4 = *(u8 *)(r1 + 10)
      50:	r3 |= r4
; dst->p4 = src->p4;
      51:	r4 = *(u8 *)(r1 + 13)
      52:	r4 <<= 8
      53:	r5 = *(u8 *)(r1 + 12)
      54:	r4 |= r5
; __u8 nh = *nexthdr;
      55:	r4 <<= 16
; switch (nh) {
      56:	r4 |= r3
      57:	r4 <<= 32
      58:	r4 |= r2
      59:	*(u64 *)(r10 - 24) = r4
      60:	r2 = *(u8 *)(r1 + 29)
      61:	r2 <<= 8
      62:	r3 = *(u8 *)(r1 + 28)
      63:	r2 |= r3
      64:	r3 = *(u8 *)(r1 + 30)
      65:	r1 = *(u8 *)(r1 + 31)
      66:	r1 <<= 8
      67:	r1 |= r3
      68:	r1 <<= 16
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r1 |= r2
      70:	*(u32 *)(r10 - 28) = r1
      71:	r1 = 512
      72:	*(u16 *)(r10 - 30) = r1
      73:	r3 = r10
      74:	r3 += -48
      75:	r1 = r6
      76:	r2 = 6
      77:	r4 = 6
      78:	r5 = 0
      79:	call 9
; nh = opthdr.nexthdr;
      80:	r7 = 4294967155 ll
      82:	r0 <<= 32
      83:	r0 s>>= 32
; if (nh == NEXTHDR_AUTH)
      84:	if r0 s< 0 goto +61 <LBB6_14>
      85:	r3 = r10
      86:	r3 += -24
; switch (nh) {
      87:	r1 = r6
      88:	r2 = 0
      89:	r4 = 6
      90:	r5 = 0
      91:	call 9
      92:	r0 <<= 32
      93:	r0 s>>= 32
      94:	if r0 s< 0 goto +51 <LBB6_14>
      95:	r3 = r10
      96:	r3 += -30
      97:	r1 = r6
      98:	r2 = 20
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	r4 = 2
     100:	r5 = 0
     101:	call 9
     102:	r0 <<= 32
     103:	r0 s>>= 32
     104:	if r0 s< 0 goto +41 <LBB6_14>
     105:	r3 = r10
     106:	r3 += -48
     107:	r1 = r6
     108:	r2 = 22
     109:	r4 = 6
; nh = opthdr.nexthdr;
     110:	r5 = 0
; if (nh == NEXTHDR_AUTH)
     111:	call 9
     112:	r0 <<= 32
     113:	r0 s>>= 32
     114:	if r0 s< 0 goto +31 <LBB6_14>
     115:	r3 = r10
     116:	r3 += -40
     117:	r1 = r6
; switch (nh) {
     118:	r2 = 28
     119:	r4 = 4
     120:	r5 = 0
     121:	call 9
     122:	r0 <<= 32
     123:	r0 s>>= 32
     124:	if r0 s< 0 goto +21 <LBB6_14>
     125:	r3 = r10
     126:	r3 += -24
     127:	r1 = r6
     128:	r2 = 32
     129:	r4 = 8
     130:	r5 = 0
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	call 9
     132:	r0 <<= 32
     133:	r0 s>>= 32
     134:	if r0 s< 0 goto +11 <LBB6_14>
     135:	r3 = r10
     136:	r3 += -28
     137:	r1 = r6
     138:	r2 = 38
     139:	r4 = 4
     140:	r5 = 0
     141:	call 9
; nh = opthdr.nexthdr;
     142:	r7 = r0
; if (nh == NEXTHDR_AUTH)
     143:	r7 <<= 32
     144:	r7 s>>= 63
     145:	r7 &= -141

LBB6_14:
     146:	r1 = r7
     147:	r1 <<= 32
     148:	r1 >>= 32
     149:	if r1 != 0 goto +30 <LBB6_18>
; switch (nh) {
     150:	r7 = *(u32 *)(r6 + 0)
     151:	r8 = *(u32 *)(r6 + 40)
     152:	r1 = r6
     153:	call 34
     154:	*(u32 *)(r10 - 20) = r0
     155:	r1 = 269485059
     156:	*(u32 *)(r10 - 24) = r1
     157:	*(u32 *)(r10 - 8) = r8
     158:	*(u32 *)(r10 - 16) = r7
     159:	if r7 < 128 goto +1 <LBB6_17>
     160:	r7 = 128

LBB6_17:
     161:	*(u32 *)(r10 - 12) = r7
     162:	r7 <<= 32
; *nexthdr = nh;
     163:	r1 = 4294967295 ll
; dst->p1 = src->p1;
     165:	r7 |= r1
; dst->p2 = src->p2;
     166:	r1 = 0
     167:	*(u32 *)(r10 - 4) = r1
; dst->p3 = src->p3;
     168:	r4 = r10
     169:	r4 += -24
; dst->p4 = src->p4;
     170:	r1 = r6
     171:	r2 = 0 ll
     173:	r3 = r7
     174:	r5 = 24
; switch (nexthdr) {
     175:	call 25
     176:	r1 = *(u32 *)(r6 + 40)
     177:	r2 = 0
     178:	call 23

LBB6_22:
     179:	exit

LBB6_18:
     180:	r1 = 2
     181:	*(u32 *)(r6 + 48) = r1
     182:	r1 = 0
     183:	*(u32 *)(r6 + 52) = r1
     184:	*(u32 *)(r6 + 56) = r7
; }
     185:	*(u32 *)(r6 + 60) = r1
     186:	*(u32 *)(r6 + 64) = r1
; switch (nexthdr) {
     187:	r8 = *(u32 *)(r6 + 0)
     188:	*(u64 *)(r10 - 16) = r1
     189:	*(u64 *)(r10 - 24) = r1
     190:	r1 = 512
     191:	*(u64 *)(r10 - 40) = r1
     192:	r7 = -r7
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	*(u8 *)(r10 - 40) = r7
     194:	r2 = r10
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r2 += -40
     196:	r1 = 0 ll
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     198:	call 1
     199:	if r0 == 0 goto +7 <LBB6_20>
     200:	r1 = *(u64 *)(r0 + 0)
     201:	r1 += 1
     202:	*(u64 *)(r0 + 0) = r1
     203:	r1 = *(u64 *)(r0 + 8)
; if (IS_ERR(ret))
     204:	r1 += r8
     205:	*(u64 *)(r0 + 8) = r1
     206:	goto +11 <LBB6_21>

LBB6_20:
     207:	*(u64 *)(r10 - 16) = r8
     208:	r1 = 1
     209:	*(u64 *)(r10 - 24) = r1
     210:	r2 = r10
     211:	r2 += -40
     212:	r3 = r10
     213:	r3 += -24
; if (IS_ERR(ret)) {
     214:	r1 = 0 ll
     216:	r4 = 0
     217:	call 2

LBB6_21:
     218:	r1 = r6
     219:	r2 = 0 ll
     221:	r3 = 1
     222:	call 12
     223:	r0 = 2
     224:	goto -46 <LBB6_22>
Disassembly of section from-container:
handle_ingress:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 0
       2:	*(u32 *)(r6 + 60) = r1
       3:	*(u32 *)(r6 + 56) = r1
       4:	*(u32 *)(r6 + 52) = r1
; struct lb6_key key = {};
       5:	*(u32 *)(r6 + 48) = r1
       6:	*(u32 *)(r6 + 64) = r1
       7:	r2 = *(u32 *)(r6 + 16)
       8:	if r2 == 8 goto +9 <LBB7_4>
       9:	if r2 == 1544 goto +13 <LBB7_5>
; tmp = a->p1 - b->p1;
      10:	r1 = 4294967157 ll
; if (!tmp)
      12:	if r2 != 56710 goto +17 <LBB7_7>
      13:	r1 = r6
; tmp = a->p2 - b->p2;
      14:	r2 = 0 ll
      16:	r3 = 10
      17:	goto +9 <LBB7_6>

LBB7_4:
; tmp = a->p1 - b->p1;
      18:	r1 = r6
; if (!tmp)
      19:	r2 = 0 ll
      21:	r3 = 7
; tmp = a->p2 - b->p2;
      22:	goto +4 <LBB7_6>

LBB7_5:
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r1 = r6
      24:	r2 = 0 ll
; tmp = a->p1 - b->p1;
      26:	r3 = 6

LBB7_6:
; if (!tmp) {
      27:	call 12
; tmp = a->p2 - b->p2;
      28:	r1 = 4294967156 ll

LBB7_7:
; tmp = a->p3 - b->p3;
      30:	r2 = 131072
; if (!tmp)
      31:	*(u32 *)(r6 + 52) = r2
; tmp = a->p4 - b->p4;
      32:	r2 = 2
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	*(u32 *)(r6 + 48) = r2
      34:	*(u32 *)(r6 + 56) = r1
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r2 = 0
      36:	*(u32 *)(r6 + 60) = r2
; dst->p1 = src->p1;
      37:	*(u32 *)(r6 + 64) = r2
      38:	r7 = *(u32 *)(r6 + 0)
; dst->p2 = src->p2;
      39:	*(u64 *)(r10 - 8) = r2
      40:	*(u64 *)(r10 - 16) = r2
; dst->p3 = src->p3;
      41:	r2 = 512
      42:	*(u64 *)(r10 - 24) = r2
; dst->p4 = src->p4;
      43:	r1 = -r1
      44:	*(u8 *)(r10 - 24) = r1
; dst->p1 = src->p1;
      45:	r2 = r10
      46:	r2 += -24
; dst->p2 = src->p2;
      47:	r1 = 0 ll
; dst->p3 = src->p3;
      49:	call 1
      50:	if r0 == 0 goto +7 <LBB7_9>
; dst->p4 = src->p4;
      51:	r1 = *(u64 *)(r0 + 0)
      52:	r1 += 1
      53:	*(u64 *)(r0 + 0) = r1
      54:	r1 = *(u64 *)(r0 + 8)
; __u8 nh = *nexthdr;
      55:	r1 += r7
; switch (nh) {
      56:	*(u64 *)(r0 + 8) = r1
      57:	goto +11 <LBB7_10>

LBB7_9:
      58:	*(u64 *)(r10 - 8) = r7
      59:	r1 = 1
      60:	*(u64 *)(r10 - 16) = r1
      61:	r2 = r10
      62:	r2 += -24
      63:	r3 = r10
      64:	r3 += -16
      65:	r1 = 0 ll
      67:	r4 = 0
      68:	call 2

LBB7_10:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r1 = r6
      70:	r2 = 0 ll
      72:	r3 = 1
      73:	call 12
      74:	r0 = 2
      75:	exit
Disassembly of section 2/12:
tail_ipv6_policy:
; {
       0:	r8 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = *(u32 *)(r8 + 48)
       2:	*(u64 *)(r10 - 248) = r1
       3:	r1 = *(u32 *)(r8 + 52)
       4:	*(u64 *)(r10 - 256) = r1
; struct lb6_key key = {};
       5:	r1 = 0
       6:	*(u16 *)(r10 - 140) = r1
       7:	*(u32 *)(r10 - 144) = r1
       8:	*(u64 *)(r10 - 152) = r1
       9:	*(u64 *)(r10 - 160) = r1
; tmp = a->p1 - b->p1;
      10:	*(u64 *)(r10 - 168) = r1
; if (!tmp)
      11:	*(u64 *)(r10 - 176) = r1
      12:	*(u64 *)(r10 - 184) = r1
      13:	*(u64 *)(r10 - 192) = r1
; tmp = a->p2 - b->p2;
      14:	*(u64 *)(r10 - 200) = r1
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r9 = 4294967162 ll
      17:	r2 = *(u32 *)(r8 + 80)
; tmp = a->p1 - b->p1;
      18:	r6 = *(u32 *)(r8 + 76)
; if (!tmp)
      19:	r3 = r6
      20:	r3 += 54
      21:	if r3 > r2 goto +174 <LBB8_57>
; tmp = a->p2 - b->p2;
      22:	*(u32 *)(r8 + 56) = r1
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r4 = *(u8 *)(r6 + 20)
      24:	*(u8 *)(r10 - 140) = r4
      25:	r1 = *(u32 *)(r6 + 38)
; tmp = a->p1 - b->p1;
      26:	*(u64 *)(r10 - 272) = r1
; if (!tmp) {
      27:	*(u32 *)(r10 - 176) = r1
; tmp = a->p2 - b->p2;
      28:	r1 = *(u32 *)(r6 + 42)
; if (!tmp) {
      29:	*(u64 *)(r10 - 280) = r1
; tmp = a->p3 - b->p3;
      30:	*(u32 *)(r10 - 172) = r1
; if (!tmp)
      31:	r1 = *(u32 *)(r6 + 46)
; tmp = a->p4 - b->p4;
      32:	*(u64 *)(r10 - 288) = r1
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	*(u32 *)(r10 - 168) = r1
      34:	r1 = *(u32 *)(r6 + 50)
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	*(u64 *)(r10 - 296) = r1
      36:	*(u32 *)(r10 - 164) = r1
; dst->p1 = src->p1;
      37:	r1 = *(u32 *)(r6 + 22)
      38:	*(u32 *)(r10 - 160) = r1
; dst->p2 = src->p2;
      39:	r1 = *(u32 *)(r6 + 26)
      40:	*(u32 *)(r10 - 156) = r1
; dst->p3 = src->p3;
      41:	r1 = *(u32 *)(r6 + 30)
      42:	*(u32 *)(r10 - 152) = r1
; dst->p4 = src->p4;
      43:	r1 = *(u32 *)(r6 + 34)
      44:	*(u32 *)(r10 - 148) = r1
; dst->p1 = src->p1;
      45:	r1 = *(u32 *)(r8 + 44)
      46:	*(u32 *)(r10 - 136) = r1
; dst->p2 = src->p2;
      47:	r1 = *(u32 *)(r10 - 136)
      48:	r1 &= 1
; dst->p3 = src->p3;
      49:	if r1 == 0 goto +20 <LBB8_3>
      50:	r7 = *(u32 *)(r10 - 136)
; dst->p4 = src->p4;
      51:	r1 = r8
      52:	call 34
      53:	*(u32 *)(r10 - 92) = r0
      54:	r1 = 269496834
; __u8 nh = *nexthdr;
      55:	*(u32 *)(r10 - 96) = r1
; switch (nh) {
      56:	*(u32 *)(r10 - 88) = r7
      57:	r1 = 0
      58:	*(u32 *)(r10 - 84) = r1
      59:	*(u32 *)(r10 - 80) = r1
      60:	r4 = r10
      61:	r4 += -96
      62:	r1 = r8
      63:	r2 = 0 ll
      65:	r3 = 4294967295 ll
      67:	r5 = 20
      68:	call 25
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r4 = *(u8 *)(r10 - 140)

LBB8_3:
      70:	*(u64 *)(r10 - 240) = r8
      71:	r3 = 40
      72:	r1 = *(u32 *)(r10 - 136)
      73:	*(u64 *)(r10 - 264) = r1
      74:	if r4 > 60 goto +105 <LBB8_28>
      75:	r1 = 1
      76:	r1 <<= r4
      77:	r2 = 1155182100513554433 ll
      79:	r1 &= r2
; nh = opthdr.nexthdr;
      80:	if r1 != 0 goto +5 <LBB8_7>
; if (nh == NEXTHDR_AUTH)
      81:	if r4 == 44 goto +111 <LBB8_32>
      82:	r9 = 4294967140 ll
      84:	if r4 == 59 goto +110 <LBB8_56>
      85:	goto +94 <LBB8_28>

LBB8_7:
      86:	r3 = r10
; switch (nh) {
      87:	r3 += -96
      88:	r8 = 2
      89:	r1 = *(u64 *)(r10 - 240)
      90:	r2 = 54
      91:	r4 = 2
      92:	call 26
      93:	r9 = 4294967162 ll
      95:	r0 <<= 32
      96:	r0 s>>= 32
      97:	if r0 s< 0 goto +97 <LBB8_56>
      98:	r4 = *(u8 *)(r10 - 96)
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	if r4 == 51 goto +1 <LBB8_10>
     100:	r8 = 3

LBB8_10:
     101:	r7 = *(u8 *)(r10 - 95)
     102:	r7 <<= r8
     103:	r3 = r7
     104:	r3 += 48
     105:	if r4 > 60 goto +74 <LBB8_28>
     106:	r1 = 1
     107:	r1 <<= r4
     108:	r2 = 1155182100513554433 ll
; nh = opthdr.nexthdr;
     110:	r1 &= r2
; if (nh == NEXTHDR_AUTH)
     111:	if r1 != 0 goto +5 <LBB8_14>
     112:	if r4 == 44 goto +80 <LBB8_32>
     113:	r9 = 4294967140 ll
     115:	if r4 == 59 goto +79 <LBB8_56>
     116:	goto +63 <LBB8_28>

LBB8_14:
     117:	r2 = r7
; switch (nh) {
     118:	r2 += 62
     119:	r3 = r10
     120:	r3 += -96
     121:	r8 = 2
     122:	r1 = *(u64 *)(r10 - 240)
     123:	r4 = 2
     124:	call 26
     125:	r0 <<= 32
     126:	r0 s>>= 32
     127:	if r0 s< 0 goto +67 <LBB8_56>
     128:	r4 = *(u8 *)(r10 - 96)
     129:	if r4 == 51 goto +1 <LBB8_17>
     130:	r8 = 3

LBB8_17:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r1 = *(u8 *)(r10 - 95)
     132:	r1 <<= r8
     133:	r7 += r1
     134:	r7 += 56
     135:	r3 = r7
     136:	if r4 > 60 goto +43 <LBB8_28>
     137:	r1 = 1
     138:	r1 <<= r4
     139:	r2 = 1155182100513554433 ll
     141:	r1 &= r2
; nh = opthdr.nexthdr;
     142:	if r1 != 0 goto +6 <LBB8_21>
; if (nh == NEXTHDR_AUTH)
     143:	if r4 == 44 goto +49 <LBB8_32>
     144:	r9 = 4294967140 ll
     146:	r3 = r7
     147:	if r4 == 59 goto +47 <LBB8_56>
     148:	goto +31 <LBB8_28>

LBB8_21:
     149:	r2 = r7
; switch (nh) {
     150:	r2 += 14
     151:	r3 = r10
     152:	r3 += -96
     153:	r8 = 2
     154:	r1 = *(u64 *)(r10 - 240)
     155:	r4 = 2
     156:	call 26
     157:	r0 <<= 32
     158:	r0 s>>= 32
     159:	if r0 s< 0 goto +35 <LBB8_56>
     160:	r4 = *(u8 *)(r10 - 96)
     161:	if r4 == 51 goto +1 <LBB8_24>
     162:	r8 = 3

LBB8_24:
; *nexthdr = nh;
     163:	r1 = *(u8 *)(r10 - 95)
; dst->p1 = src->p1;
     164:	r1 <<= r8
     165:	r7 += r1
; dst->p2 = src->p2;
     166:	r7 += 8
     167:	r3 = r7
; dst->p3 = src->p3;
     168:	if r4 > 60 goto +11 <LBB8_28>
     169:	r1 = 1
; dst->p4 = src->p4;
     170:	r1 <<= r4
     171:	r2 = 1155182100513554433 ll
     173:	r1 &= r2
     174:	if r1 != 0 goto +201 <LBB8_55>
; switch (nexthdr) {
     175:	if r4 == 44 goto +17 <LBB8_32>
     176:	r9 = 4294967140 ll
     178:	r3 = r7
     179:	if r4 == 59 goto +15 <LBB8_56>

LBB8_28:
     180:	r7 = 0
     181:	*(u8 *)(r10 - 140) = r4
     182:	r1 = r4
     183:	r1 &= 255
     184:	if r1 == 58 goto +56 <LBB8_34>
; }
     185:	r8 = *(u64 *)(r10 - 240)
     186:	if r1 == 17 goto +50 <LBB8_33>
; switch (nexthdr) {
     187:	r2 = 0
     188:	*(u64 *)(r10 - 304) = r2
     189:	if r1 != 6 goto +54 <LBB8_35>
     190:	r1 = 16
     191:	*(u64 *)(r10 - 304) = r1
     192:	goto +51 <LBB8_35>

LBB8_32:
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r9 = 4294967139 ll

LBB8_56:
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r8 = *(u64 *)(r10 - 240)

LBB8_57:
     196:	r1 = r9
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r1 <<= 32
     198:	r1 >>= 32
     199:	r2 = 1
     200:	if r1 == 2 goto +1 <LBB8_59>
     201:	r2 = 0

LBB8_59:
     202:	r1 >>= 31
     203:	r1 |= r2
; if (IS_ERR(ret))
     204:	if r1 == 0 goto +1165 <LBB8_172>
     205:	r1 = 2
     206:	*(u32 *)(r8 + 48) = r1
     207:	r1 = 4112
     208:	*(u32 *)(r8 + 60) = r1
     209:	r1 = *(u64 *)(r10 - 256)
     210:	*(u32 *)(r8 + 64) = r1
     211:	r1 = *(u64 *)(r10 - 248)
     212:	r1 <<= 16
     213:	r1 |= 2
; if (IS_ERR(ret)) {
     214:	*(u32 *)(r8 + 52) = r1
     215:	*(u32 *)(r8 + 56) = r9
     216:	r6 = *(u32 *)(r8 + 0)
     217:	r1 = 0
     218:	*(u64 *)(r10 - 88) = r1
     219:	*(u64 *)(r10 - 96) = r1
     220:	r1 = 256
     221:	*(u64 *)(r10 - 136) = r1
     222:	r9 = -r9
     223:	*(u8 *)(r10 - 136) = r9
     224:	r2 = r10
     225:	r2 += -136
     226:	r1 = 0 ll
; if (ret == DROP_UNKNOWN_L4)
     228:	call 1
     229:	if r0 == 0 goto +1123 <LBB8_170>
     230:	r1 = *(u64 *)(r0 + 0)
     231:	r1 += 1
     232:	*(u64 *)(r0 + 0) = r1
     233:	r1 = *(u64 *)(r0 + 8)
     234:	r1 += r6
     235:	*(u64 *)(r0 + 8) = r1
     236:	goto +1127 <LBB8_171>

LBB8_33:
     237:	r1 = 6
     238:	*(u64 *)(r10 - 304) = r1
     239:	r7 = 32
     240:	goto +3 <LBB8_35>

LBB8_34:
; if (key->dport) {
     241:	r1 = 2
     242:	*(u64 *)(r10 - 304) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r8 = *(u64 *)(r10 - 240)

LBB8_35:
; uint32_t hash = get_hash_recalc(skb);
     244:	r1 = r3
     245:	r1 += 14
; struct debug_msg msg = {
     246:	*(u64 *)(r10 - 312) = r1
     247:	r1 = *(u32 *)(r6 + 50)
     248:	*(u16 *)(r10 - 200) = r1
     249:	r2 = r1
     250:	r2 &= 65535
     251:	*(u64 *)(r10 - 320) = r3
     252:	if r2 == 0 goto +58 <LBB8_43>
     253:	r2 = *(u32 *)(r6 + 38)
     254:	*(u32 *)(r10 - 96) = r2
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	r2 = *(u32 *)(r6 + 42)
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	*(u32 *)(r10 - 92) = r2
     257:	r2 = 4294901760 ll
     259:	r1 &= r2
     260:	r2 = *(u32 *)(r6 + 46)
     261:	*(u32 *)(r10 - 84) = r1
     262:	*(u32 *)(r10 - 88) = r2
     263:	r3 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r3 += -96
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	r1 = r8
     266:	r2 = 38
     267:	r4 = 16
; if (svc && svc->count != 0)
     268:	r5 = 0
     269:	call 9
     270:	r0 <<= 32
     271:	r0 >>= 32
     272:	r1 = 1
     273:	if r0 == 2 goto +1 <LBB8_38>
; key->dport = 0;
     274:	r1 = 0

LBB8_38:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r0 >>= 31
; uint32_t hash = get_hash_recalc(skb);
     276:	r0 |= r1
     277:	r9 = 4294967155 ll
; struct debug_msg msg = {
     279:	if r0 != 0 goto +28 <LBB8_41>
     280:	r1 = *(u64 *)(r10 - 304)
     281:	if r1 == 0 goto +27 <LBB8_42>
     282:	r1 = 0
     283:	*(u32 *)(r10 - 136) = r1
     284:	r1 = r10
     285:	r1 += -200
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	r3 = r10
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r3 += -136
     288:	r2 = 4
     289:	r4 = 4
     290:	r5 = 0
     291:	call 28
     292:	r1 = *(u64 *)(r10 - 304)
     293:	r1 &= 65535
     294:	r2 = *(u64 *)(r10 - 312)
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	r2 += r1
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r5 = r7
     297:	r5 |= 16
     298:	r5 &= 65535
; if (svc && svc->count != 0)
     299:	r1 = r8
     300:	r3 = 0
     301:	r4 = r0
     302:	call 11
     303:	r9 = 4294967142 ll
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r0 <<= 32
     306:	r0 s>>= 32
; uint32_t hash = get_hash_recalc(skb);
     307:	if r0 s> -1 goto +1 <LBB8_42>

LBB8_41:
     308:	goto -113 <LBB8_57>

LBB8_42:
; struct debug_msg msg = {
     309:	r4 = *(u8 *)(r10 - 140)
     310:	r3 = *(u64 *)(r10 - 320)

LBB8_43:
     311:	r1 = 0
     312:	*(u8 *)(r10 - 139) = r1
     313:	*(u16 *)(r10 - 136) = r1
     314:	r1 = r4
     315:	r1 &= 255
     316:	r2 = 0 ll
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	if r1 == 6 goto +2 <LBB8_45>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r2 = 0 ll

LBB8_45:
     321:	*(u64 *)(r10 - 336) = r4
     322:	*(u64 *)(r10 - 328) = r2
     323:	if r1 == 6 goto +27 <LBB8_53>
     324:	if r1 == 17 goto +76 <LBB8_65>
     325:	r9 = 4294967159 ll
     327:	if r1 != 58 goto -132 <LBB8_57>
     328:	r3 = r10
     329:	r3 += -96
     330:	r6 = 1
     331:	r1 = r8
     332:	r2 = *(u64 *)(r10 - 312)
; __u8 flags = tuple->flags;
     333:	r4 = 1
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	call 26
; union tcp_flags tcp_flags = { 0 };
     335:	r0 <<= 32
     336:	r0 s>>= 32
; tuple->flags = TUPLE_F_SERVICE;
     337:	if r0 s< 0 goto +52 <LBB8_62>
     338:	r1 = 0
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	*(u32 *)(r10 - 144) = r1
     340:	r1 = *(u8 *)(r10 - 96)
     341:	r2 = r1
     342:	r2 += -1
     343:	if r2 < 4 goto +49 <LBB8_63>
     344:	if r1 == 128 goto +53 <LBB8_64>
; switch (tuple->nexthdr) {
     345:	if r1 == 129 goto +1 <LBB8_52>
     346:	goto +66 <LBB8_66>

LBB8_52:
     347:	r1 = 128
     348:	*(u16 *)(r10 - 144) = r1
     349:	r6 = 0
     350:	goto +62 <LBB8_66>

LBB8_53:
; __u8 type;
     351:	r2 = r3
     352:	r2 += 26
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	r3 = r10
     354:	r3 += -136
     355:	r1 = r8
     356:	r4 = 2
     357:	call 26
     358:	r9 = 4294967161 ll
     360:	r0 <<= 32
     361:	r0 s>>= 32
; tuple->dport = 0;
     362:	if r0 s< 0 goto -167 <LBB8_57>
     363:	r6 = *(u8 *)(r10 - 136)
; tuple->sport = 0;
     364:	r3 = r10
     365:	r3 += -144
     366:	r1 = r8
; switch (type) {
     367:	r2 = *(u64 *)(r10 - 312)
     368:	r4 = 4
     369:	call 26
     370:	r6 &= 1
     371:	r6 += 1
     372:	r0 <<= 32
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r0 s>>= 32
     374:	if r0 s< 0 goto -179 <LBB8_57>
     375:	goto +37 <LBB8_66>

LBB8_55:
     376:	r7 += 14
     377:	r3 = r10
     378:	r3 += -96
     379:	r1 = *(u64 *)(r10 - 240)
     380:	r2 = r7
     381:	r4 = 2
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	call 26
     383:	r9 = r0
     384:	r9 <<= 32
     385:	r9 s>>= 32
     386:	r9 >>= 31
     387:	r9 &= 22
     388:	r9 += -156
     389:	goto -195 <LBB8_56>

LBB8_62:
     390:	r9 = 4294967161 ll
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     392:	goto -197 <LBB8_57>

LBB8_63:
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	r1 = *(u8 *)(r10 - 139)
     394:	r1 |= 2
     395:	*(u8 *)(r10 - 139) = r1
     396:	r6 = 0
     397:	goto +15 <LBB8_66>

LBB8_64:
     398:	r1 = 128
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	*(u16 *)(r10 - 142) = r1
     400:	goto +12 <LBB8_66>

LBB8_65:
     401:	r3 = r10
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r3 += -144
     403:	r1 = r8
     404:	r2 = *(u64 *)(r10 - 312)
     405:	r4 = 4
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	call 26
     407:	r6 = 1
     408:	r9 = 4294967161 ll
     410:	r0 <<= 32
     411:	r0 s>>= 32
     412:	if r0 s< 0 goto -217 <LBB8_57>

LBB8_66:
     413:	*(u64 *)(r10 - 352) = r6
     414:	*(u64 *)(r10 - 360) = r7
     415:	r6 = *(u16 *)(r10 - 144)
     416:	r7 = *(u16 *)(r10 - 142)
     417:	r8 = *(u32 *)(r10 - 164)
     418:	r9 = *(u32 *)(r10 - 148)
     419:	r1 = *(u64 *)(r10 - 240)
; tuple->flags |= TUPLE_F_RELATED;
     420:	call 34
     421:	*(u32 *)(r10 - 92) = r0
     422:	r1 = 269496066
     423:	*(u32 *)(r10 - 96) = r1
; break;
     424:	*(u32 *)(r10 - 88) = r9
     425:	*(u32 *)(r10 - 84) = r8
; tuple->sport = type;
     426:	r8 = *(u64 *)(r10 - 240)
     427:	r7 = be32 r7
     428:	r1 = 4294901760 ll
     430:	r7 &= r1
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	r6 = be16 r6
     432:	r7 |= r6
     433:	*(u32 *)(r10 - 80) = r7
     434:	r4 = r10
     435:	r4 += -96
     436:	r1 = r8
     437:	r2 = 0 ll
     439:	r3 = 4294967295 ll
     441:	r5 = 20
     442:	call 25
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	r6 = *(u8 *)(r10 - 139)
     444:	r7 = *(u8 *)(r10 - 140)
     445:	r1 = r8
     446:	call 34
     447:	*(u32 *)(r10 - 92) = r0
     448:	r1 = 269496322
     449:	*(u32 *)(r10 - 96) = r1
     450:	r7 <<= 8
     451:	r7 |= r6
     452:	*(u32 *)(r10 - 88) = r7
     453:	r9 = 0
     454:	*(u32 *)(r10 - 84) = r9
     455:	*(u32 *)(r10 - 80) = r9
     456:	r4 = r10
     457:	r4 += -96
     458:	r1 = r8
     459:	r2 = 0 ll
     461:	r3 = 4294967295 ll
     463:	r5 = 20
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	call 25
     465:	r1 = *(u8 *)(r10 - 135)
     466:	*(u64 *)(r10 - 368) = r1
     467:	r1 = *(u8 *)(r10 - 136)
     468:	*(u64 *)(r10 - 376) = r1
     469:	r2 = r10
     470:	r2 += -176
; uint32_t hash = get_hash_recalc(skb);
     471:	r6 = *(u64 *)(r10 - 328)
     472:	r1 = r6
; struct debug_msg msg = {
     473:	call 1
     474:	r7 = r0
     475:	if r7 == 0 goto +141 <LBB8_86>
     476:	r8 = *(u16 *)(r7 + 38)
     477:	r6 = *(u32 *)(r7 + 32)
     478:	r1 = *(u64 *)(r10 - 240)
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	call 34
     480:	*(u32 *)(r10 - 92) = r0
     481:	r1 = 269486082
     482:	*(u32 *)(r10 - 96) = r1
     483:	*(u32 *)(r10 - 88) = r6
     484:	*(u32 *)(r10 - 84) = r8
     485:	r8 = *(u64 *)(r10 - 240)
     486:	*(u32 *)(r10 - 80) = r9
     487:	r4 = r10
; struct debug_msg msg = {
     488:	r4 += -96
     489:	r1 = r8
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     490:	r2 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     492:	r3 = 4294967295 ll
     494:	r5 = 20
     495:	call 25
     496:	r1 = *(u16 *)(r7 + 36)
     497:	r2 = r1
     498:	r2 &= 3
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     499:	r6 = *(u64 *)(r10 - 352)
     500:	if r2 == 3 goto +43 <LBB8_74>
; uint32_t hash = get_hash_recalc(skb);
     501:	r8 = 60
     502:	r2 = *(u64 *)(r10 - 336)
; struct debug_msg msg = {
     503:	r2 &= 255
     504:	if r2 != 6 goto +16 <LBB8_71>
     505:	r2 = *(u64 *)(r10 - 376)
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     506:	r2 ^= 1
     507:	r2 &= 255
; struct debug_msg msg = {
     508:	r3 = r1
     509:	r3 >>= 4
     510:	r3 |= r2
     511:	r2 = r3
     512:	r2 <<= 4
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     513:	r2 &= 16
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     514:	r1 &= 65519
     515:	r2 |= r1
     516:	*(u16 *)(r7 + 36) = r2
     517:	r3 &= 1
     518:	r8 = 60
     519:	if r3 == 0 goto +1 <LBB8_71>
     520:	r8 = 21600

LBB8_71:
     521:	call 5
     522:	r0 /= 1000000000
; if ((entry = map_lookup_elem(map, tuple))) {
     523:	r8 += r0
     524:	*(u32 *)(r7 + 32) = r8
     525:	r2 = *(u8 *)(r7 + 43)
     526:	r1 = r2
     527:	r3 = *(u64 *)(r10 - 368)
     528:	r1 |= r3
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     529:	r3 = r1
     530:	r3 &= 255
     531:	r8 = *(u64 *)(r10 - 240)
     532:	if r2 != r3 goto +8 <LBB8_73>
; uint32_t hash = get_hash_recalc(skb);
     533:	r2 = *(u32 *)(r7 + 52)
     534:	r2 += 5
; struct debug_msg msg = {
     535:	r3 = r0
     536:	r3 <<= 32
     537:	r3 >>= 32
     538:	r2 <<= 32
     539:	r2 >>= 32
     540:	if r2 >= r3 goto +3 <LBB8_74>

LBB8_73:
     541:	*(u8 *)(r7 + 43) = r1
     542:	*(u32 *)(r7 + 52) = r0
     543:	r9 = 128

LBB8_74:
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     544:	r1 = *(u16 *)(r7 + 38)
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     545:	*(u64 *)(r10 - 344) = r1
     546:	r1 = *(u8 *)(r7 + 36)
     547:	r1 &= 4
     548:	if r1 == 0 goto +4 <LBB8_77>
     549:	r1 = *(u32 *)(r8 + 60)
     550:	if r1 != 0 goto +2 <LBB8_77>
     551:	r1 = 2
; return !entry->rx_closing || !entry->tx_closing;
     552:	*(u32 *)(r8 + 60) = r1

LBB8_77:
     553:	r1 = 1
     554:	lock *(u64 *)(r7 + 0) += r1
; if (ct_entry_alive(entry)) {
     555:	r1 = *(u32 *)(r8 + 0)
     556:	lock *(u64 *)(r7 + 8) += r1
; if (tcp) {
     557:	if r6 == 2 goto +242 <LBB8_108>
     558:	r6 <<= 32
; entry->seen_non_syn |= !syn;
     559:	r6 >>= 32
     560:	if r6 != 1 goto +267 <LBB8_112>
     561:	r1 = *(u16 *)(r7 + 36)
     562:	r2 = r1
     563:	r2 &= 1
     564:	r3 = r1
     565:	r3 >>= 1
     566:	r3 &= 1
     567:	r3 = -r3
     568:	if r2 == r3 goto +259 <LBB8_112>
     569:	r2 = r1
     570:	r2 &= 65532
; if (entry->seen_non_syn)
     571:	*(u16 *)(r7 + 36) = r2
     572:	r8 = 60
     573:	r2 = *(u64 *)(r10 - 336)
     574:	r2 &= 255
; return ktime_get_ns();
     575:	if r2 != 6 goto +16 <LBB8_83>
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     576:	r3 = *(u64 *)(r10 - 376)
; entry->lifetime = now + lifetime;
     577:	r3 ^= 1
     578:	r3 &= 255
; seen_flags |= *accumulated_flags;
     579:	r2 = r1
     580:	r2 >>= 4
     581:	r2 |= r3
     582:	r3 = r2
     583:	r3 <<= 4
     584:	r3 &= 16
; if (*last_report + CT_REPORT_INTERVAL < now ||
     585:	r1 &= 65516
     586:	r3 |= r1
     587:	*(u16 *)(r7 + 36) = r3
     588:	r2 &= 1
     589:	r8 = 60
     590:	if r2 == 0 goto +1 <LBB8_83>
     591:	r8 = 21600

LBB8_83:
     592:	call 5
     593:	r0 /= 1000000000
; *accumulated_flags = seen_flags;
     594:	r8 += r0
; *last_report = now;
     595:	*(u32 *)(r7 + 32) = r8
; ct_state->slave = entry->slave;
     596:	r2 = *(u8 *)(r7 + 43)
; ct_state->rev_nat_index = entry->rev_nat_index;
     597:	r1 = r2
     598:	r3 = *(u64 *)(r10 - 368)
; ct_state->loopback = entry->lb_loopback;
     599:	r1 |= r3
     600:	r3 = r1
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
     601:	r3 &= 255
     602:	r8 = *(u64 *)(r10 - 240)
     603:	if r2 != r3 goto +9 <LBB8_85>
     604:	r9 = 0
     605:	r2 = *(u32 *)(r7 + 52)
; skb->cb[CB_NAT46_STATE] = NAT46;
     606:	r2 += 5
     607:	r3 = r0
     608:	r3 <<= 32
; __sync_fetch_and_add(&entry->tx_packets, 1);
     609:	r3 >>= 32
     610:	r2 <<= 32
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
     611:	r2 >>= 32
     612:	if r2 >= r3 goto +215 <LBB8_112>

LBB8_85:
     613:	*(u8 *)(r7 + 43) = r1
     614:	*(u32 *)(r7 + 52) = r0
; switch (action) {
     615:	r9 = 128
     616:	goto +211 <LBB8_112>

LBB8_86:
     617:	r2 = *(u8 *)(r10 - 139)
     618:	r1 = r2
; ret = entry->rx_closing + entry->tx_closing;
     619:	r1 |= 1
     620:	r3 = r2
     621:	r3 &= 1
     622:	if r3 == 0 goto +2 <LBB8_88>
     623:	r2 &= 254
     624:	r1 = r2

LBB8_88:
; if (unlikely(ret >= 1)) {
     625:	r2 = *(u64 *)(r10 - 160)
     626:	r3 = *(u64 *)(r10 - 176)
     627:	*(u64 *)(r10 - 160) = r3
     628:	r3 = *(u64 *)(r10 - 168)
; entry->tx_closing = 0;
     629:	r4 = *(u64 *)(r10 - 152)
     630:	*(u64 *)(r10 - 168) = r4
     631:	*(u64 *)(r10 - 152) = r3
     632:	*(u64 *)(r10 - 176) = r2
; if (tcp) {
     633:	r2 = *(u16 *)(r10 - 142)
     634:	r3 = *(u16 *)(r10 - 144)
     635:	*(u16 *)(r10 - 142) = r3
; entry->seen_non_syn |= !syn;
     636:	*(u16 *)(r10 - 144) = r2
     637:	*(u8 *)(r10 - 139) = r1
     638:	r1 = *(u8 *)(r10 - 135)
     639:	*(u64 *)(r10 - 368) = r1
     640:	r1 = *(u8 *)(r10 - 136)
     641:	*(u64 *)(r10 - 376) = r1
     642:	r2 = r10
     643:	r2 += -176
     644:	r1 = r6
     645:	call 1
     646:	r7 = r0
     647:	r9 = 128
; if (entry->seen_non_syn)
     648:	r4 = 0
     649:	r1 = 0
     650:	*(u64 *)(r10 - 344) = r1
     651:	r6 = 0
; return ktime_get_ns();
     652:	if r7 == 0 goto +209 <LBB8_117>
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     653:	r8 = *(u16 *)(r7 + 38)
; entry->lifetime = now + lifetime;
     654:	r9 = *(u32 *)(r7 + 32)
     655:	r1 = *(u64 *)(r10 - 240)
     656:	call 34
; seen_flags |= *accumulated_flags;
     657:	*(u32 *)(r10 - 92) = r0
     658:	r1 = 269486082
     659:	*(u32 *)(r10 - 96) = r1
     660:	*(u32 *)(r10 - 88) = r9
     661:	*(u32 *)(r10 - 84) = r8
     662:	r8 = *(u64 *)(r10 - 240)
     663:	r1 = 0
; if (*last_report + CT_REPORT_INTERVAL < now ||
     664:	*(u32 *)(r10 - 80) = r1
     665:	r4 = r10
     666:	r4 += -96
     667:	r1 = r8
     668:	r2 = 0 ll
     670:	r3 = 4294967295 ll
     672:	r5 = 20
; *accumulated_flags = seen_flags;
     673:	call 25
; *last_report = now;
     674:	r1 = *(u16 *)(r7 + 36)
     675:	r2 = r1
     676:	r2 &= 3
     677:	r9 = 128
     678:	if r2 == 3 goto +44 <LBB8_96>
     679:	r8 = 60
; switch(ret) {
     680:	r2 = *(u64 *)(r10 - 336)
     681:	r2 &= 255
; tuple->flags = flags;
     682:	if r2 != 6 goto +16 <LBB8_93>
     683:	r2 = *(u64 *)(r10 - 376)
     684:	r2 ^= 1
     685:	r2 &= 255
; if (IS_ERR(ret))
     686:	r3 = r1
     687:	r3 >>= 4
     688:	r3 |= r2
     689:	r2 = r3
     690:	r2 <<= 4
     691:	r2 &= 16
     692:	r1 &= 65519
     693:	r2 |= r1
     694:	*(u16 *)(r7 + 36) = r2
     695:	r3 &= 1
; dst->p4 = src->p4;
     696:	r8 = 60
; dst->p3 = src->p3;
     697:	if r3 == 0 goto +1 <LBB8_93>
     698:	r8 = 21600

LBB8_93:
; dst->p2 = src->p2;
     699:	call 5
; dst->p1 = src->p1;
     700:	r0 /= 1000000000
     701:	r8 += r0
; if (tuple->nexthdr == IPPROTO_TCP) {
     702:	*(u32 *)(r7 + 32) = r8
     703:	r2 = *(u8 *)(r7 + 43)
; union tcp_flags tcp_flags = { 0 };
     704:	r1 = r2
     705:	r3 = *(u64 *)(r10 - 368)
; tuple->flags = TUPLE_F_IN;
     706:	r1 |= r3
     707:	r3 = r1
; ret = ct_lookup6(get_ct_map6(tuple), tuple, skb, l4_off, CT_EGRESS,
     708:	r3 &= 255
     709:	r8 = *(u64 *)(r10 - 240)
     710:	if r2 != r3 goto +9 <LBB8_95>
     711:	r9 = 0
     712:	r2 = *(u32 *)(r7 + 52)
     713:	r2 += 5
     714:	r3 = r0
; switch (tuple->nexthdr) {
     715:	r3 <<= 32
     716:	r3 >>= 32
     717:	r2 <<= 32
     718:	r2 >>= 32
     719:	if r2 >= r3 goto +3 <LBB8_96>

LBB8_95:
     720:	*(u8 *)(r7 + 43) = r1
     721:	*(u32 *)(r7 + 52) = r0
; __u8 type;
     722:	r9 = 128

LBB8_96:
     723:	r1 = *(u16 *)(r7 + 38)
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     724:	*(u64 *)(r10 - 344) = r1
     725:	r1 = *(u8 *)(r7 + 36)
     726:	r1 &= 4
     727:	if r1 == 0 goto +4 <LBB8_99>
     728:	r1 = *(u32 *)(r8 + 60)
     729:	if r1 != 0 goto +2 <LBB8_99>
     730:	r1 = 2
     731:	*(u32 *)(r8 + 60) = r1

LBB8_99:
     732:	r6 = 1
; tuple->dport = 0;
     733:	r1 = 1
     734:	lock *(u64 *)(r7 + 0) += r1
; tuple->sport = 0;
     735:	r1 = *(u32 *)(r8 + 0)
     736:	lock *(u64 *)(r7 + 8) += r1
; tuple->dport = 0;
     737:	r1 = *(u64 *)(r10 - 352)
     738:	r4 = 0
     739:	if r1 == 2 goto +93 <LBB8_113>
; switch (type) {
     740:	r1 <<= 32
     741:	r1 >>= 32
     742:	if r1 != 1 goto +119 <LBB8_117>
     743:	r1 = *(u16 *)(r7 + 36)
     744:	r2 = r1
     745:	r2 &= 1
; tuple->dport = ICMPV6_ECHO_REQUEST;
     746:	r3 = r1
     747:	r3 >>= 1
     748:	r3 &= 1
     749:	r3 = -r3
     750:	if r2 == r3 goto +111 <LBB8_117>
     751:	r2 = r1
     752:	r2 &= 65532
     753:	*(u16 *)(r7 + 36) = r2
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     754:	r8 = 60
     755:	r2 = *(u64 *)(r10 - 336)
     756:	r2 &= 255
     757:	if r2 != 6 goto +16 <LBB8_105>
     758:	r3 = *(u64 *)(r10 - 376)
     759:	r3 ^= 1
     760:	r3 &= 255
     761:	r2 = r1
     762:	r2 >>= 4
     763:	r2 |= r3
     764:	r3 = r2
     765:	r3 <<= 4
     766:	r3 &= 16
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     767:	r1 &= 65516
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     768:	r3 |= r1
     769:	*(u16 *)(r7 + 36) = r3
     770:	r2 &= 1
     771:	r8 = 60
     772:	if r2 == 0 goto +1 <LBB8_105>
     773:	r8 = 21600

LBB8_105:
     774:	call 5
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     775:	r0 /= 1000000000
     776:	r8 += r0
     777:	*(u32 *)(r7 + 32) = r8
     778:	r2 = *(u8 *)(r7 + 43)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     779:	r1 = r2
     780:	r3 = *(u64 *)(r10 - 368)
     781:	r1 |= r3
     782:	r3 = r1
     783:	r3 &= 255
     784:	r8 = *(u64 *)(r10 - 240)
     785:	r4 = 0
; tuple->flags |= TUPLE_F_RELATED;
     786:	if r2 != r3 goto +9 <LBB8_107>
     787:	r9 = 0
     788:	r2 = *(u32 *)(r7 + 52)
     789:	r2 += 5
; break;
     790:	r3 = r0
     791:	r3 <<= 32
     792:	r3 >>= 32
     793:	r2 <<= 32
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
     794:	r2 >>= 32
     795:	if r2 >= r3 goto +66 <LBB8_117>

LBB8_107:
     796:	*(u8 *)(r7 + 43) = r1
     797:	*(u32 *)(r7 + 52) = r0
     798:	r9 = 128
     799:	goto +62 <LBB8_117>

LBB8_108:
     800:	r1 = *(u16 *)(r7 + 36)
     801:	r1 |= 1
     802:	*(u16 *)(r7 + 36) = r1
; if (dir == CT_INGRESS)
     803:	r9 = 128
     804:	r1 &= 3
; return !entry->rx_closing || !entry->tx_closing;
     805:	if r1 != 3 goto +22 <LBB8_112>
; if (ct_entry_alive(entry))
     806:	call 5
; return ktime_get_ns();
     807:	r0 /= 1000000000
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     808:	r1 = r0
; entry->lifetime = now + lifetime;
     809:	r1 += 10
     810:	*(u32 *)(r7 + 32) = r1
     811:	r2 = *(u8 *)(r7 + 43)
; seen_flags |= *accumulated_flags;
     812:	r1 = r2
     813:	r3 = *(u64 *)(r10 - 368)
     814:	r1 |= r3
     815:	r3 = r1
     816:	r3 &= 255
     817:	if r2 != r3 goto +8 <LBB8_111>
; if (*last_report + CT_REPORT_INTERVAL < now ||
     818:	r2 = *(u32 *)(r7 + 52)
     819:	r2 += 5
     820:	r3 = r0
     821:	r3 <<= 32
     822:	r3 >>= 32
     823:	r2 <<= 32
     824:	r2 >>= 32
     825:	if r2 >= r3 goto +2 <LBB8_112>

LBB8_111:
     826:	*(u8 *)(r7 + 43) = r1
; *accumulated_flags = seen_flags;
     827:	*(u32 *)(r7 + 52) = r0

LBB8_112:
; *last_report = now;
     828:	r6 = *(u8 *)(r10 - 139)
     829:	r6 >>= 1
     830:	r6 &= 1
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
     831:	r6 |= 2
     832:	goto +30 <LBB8_118>

LBB8_113:
     833:	r1 = *(u16 *)(r7 + 36)
     834:	r1 |= 1
     835:	*(u16 *)(r7 + 36) = r1
; uint32_t hash = get_hash_recalc(skb);
     836:	r9 = 128
     837:	r1 &= 3
; struct debug_msg msg = {
     838:	if r1 != 3 goto +23 <LBB8_117>
     839:	call 5
     840:	r4 = 0
     841:	r0 /= 1000000000
     842:	r1 = r0
     843:	r1 += 10
     844:	*(u32 *)(r7 + 32) = r1
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
     845:	r2 = *(u8 *)(r7 + 43)
; struct debug_msg msg = {
     846:	r1 = r2
     847:	r3 = *(u64 *)(r10 - 368)
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
     848:	r1 |= r3
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     849:	r3 = r1
     850:	r3 &= 255
     851:	if r2 != r3 goto +8 <LBB8_116>
     852:	r2 = *(u32 *)(r7 + 52)
     853:	r2 += 5
     854:	r3 = r0
     855:	r3 <<= 32
     856:	r3 >>= 32
; switch(ret) {
     857:	r2 <<= 32
     858:	r2 >>= 32
     859:	if r2 >= r3 goto +2 <LBB8_117>

LBB8_116:
     860:	*(u8 *)(r7 + 43) = r1
     861:	*(u32 *)(r7 + 52) = r0

LBB8_117:
     862:	*(u32 *)(r8 + 60) = r4

LBB8_118:
     863:	r1 = r8
     864:	call 34
     865:	*(u32 *)(r10 - 92) = r0
     866:	r1 = 269487874
     867:	*(u32 *)(r10 - 96) = r1
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     868:	*(u64 *)(r10 - 328) = r6
     869:	*(u32 *)(r10 - 88) = r6
     870:	r1 = 0
     871:	*(u32 *)(r10 - 80) = r1
     872:	r7 = *(u64 *)(r10 - 344)
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     873:	r7 &= 65535
     874:	*(u32 *)(r10 - 84) = r7
; struct lb6_service *svc;
     875:	r4 = r10
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     876:	r4 += -96
     877:	r1 = r8
     878:	r2 = 0 ll
     880:	r3 = 4294967295 ll
; skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
     882:	r5 = 20
     883:	call 25
     884:	r1 = 1500
     885:	r6 = *(u16 *)(r10 - 144)
     886:	if r6 == 13568 goto +1 <LBB8_120>
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     887:	r1 = r9

LBB8_120:
     888:	*(u64 *)(r10 - 352) = r1
; return get_hash_recalc(skb);
     889:	if r7 != 0 goto +482 <LBB8_173>

LBB8_122:
     890:	r1 = *(u8 *)(r10 - 140)
     891:	*(u16 *)(r10 - 132) = r6
; if (weight) {
     892:	r9 = *(u64 *)(r10 - 248)
     893:	*(u32 *)(r10 - 136) = r9
; struct lb6_key *key,
     894:	r7 = 0
; seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
     895:	*(u8 *)(r10 - 129) = r7
     896:	*(u64 *)(r10 - 336) = r1
     897:	*(u8 *)(r10 - 130) = r1
; if (seq && seq->count != 0)
     898:	r2 = r10
     899:	r2 += -136
     900:	r1 = 0 ll
; slave = lb_next_rr(skb, seq, hash);
     902:	call 1
; __u8 offset = hash % seq->count;
     903:	r8 = r0
     904:	if r8 == 0 goto +544 <LBB8_178>
     905:	r7 = *(u64 *)(r10 - 240)
     906:	r1 = r7
     907:	call 34
; if (offset < LB_RR_MAX_SEQ) {
     908:	*(u32 *)(r10 - 92) = r0
     909:	r1 = 269497090
; slave = seq->idx[offset] + 1;
     910:	*(u32 *)(r10 - 96) = r1
     911:	*(u32 *)(r10 - 88) = r9
     912:	r1 = 2
; uint32_t hash = get_hash_recalc(skb);
     913:	*(u32 *)(r10 - 84) = r1
     914:	r6 <<= 16
; struct debug_msg msg = {
     915:	r1 = *(u64 *)(r10 - 336)
     916:	r6 |= r1
     917:	*(u32 *)(r10 - 80) = r6
     918:	r4 = r10
     919:	r4 += -96
     920:	r1 = r7
     921:	r2 = 0 ll
     923:	r3 = 4294967295 ll
     925:	r5 = 20
; uint32_t hash = get_hash_recalc(skb);
     926:	call 25
     927:	r1 = 1
; struct debug_msg msg = {
     928:	lock *(u64 *)(r8 + 8) += r1
     929:	r1 = *(u32 *)(r7 + 0)

LBB8_124:
     930:	lock *(u64 *)(r8 + 16) += r1
     931:	r7 = *(u16 *)(r8 + 0)

LBB8_125:
     932:	r6 = *(u64 *)(r10 - 328)

LBB8_126:
     933:	r8 = *(u64 *)(r10 - 240)

LBB8_127:
; slave = (hash % count) + 1;
     934:	r1 = *(u64 *)(r10 - 264)
     935:	r1 &= 1
     936:	if r1 == 0 goto +1 <LBB8_129>
     937:	r7 = 0

LBB8_129:
     938:	if r6 != 0 goto +111 <LBB8_139>
     939:	r1 = *(u16 *)(r10 - 144)
     940:	*(u16 *)(r10 - 196) = r1
; struct debug_msg msg = {
     941:	r1 = *(u64 *)(r10 - 248)
     942:	*(u32 *)(r10 - 184) = r1
     943:	r3 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     945:	r1 = *(u8 *)(r10 - 140)
     946:	if r1 == 6 goto +2 <LBB8_132>
     947:	r3 = 0 ll

LBB8_132:
     949:	r2 = 0
     950:	*(u64 *)(r10 - 56) = r2
     951:	*(u64 *)(r10 - 64) = r2
     952:	*(u64 *)(r10 - 48) = r2
     953:	*(u64 *)(r10 - 72) = r2
; struct ct_entry entry = { };
     954:	*(u64 *)(r10 - 80) = r2
     955:	*(u64 *)(r10 - 88) = r2
     956:	*(u64 *)(r10 - 96) = r2
     957:	r2 = *(u16 *)(r10 - 180)
     958:	*(u16 *)(r10 - 56) = r2
     959:	r6 = *(u16 *)(r10 - 200)
     960:	*(u16 *)(r10 - 58) = r6
; bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
     961:	r2 = *(u16 *)(r10 - 198)
     962:	r2 <<= 3
; entry.rev_nat_index = ct_state->rev_nat_index;
     963:	r2 &= 8
     964:	*(u16 *)(r10 - 60) = r2
; entry.slave = ct_state->slave;
     965:	if r1 != 6 goto +1 <LBB8_134>
; entry.lb_loopback = ct_state->loopback;
     966:	*(u16 *)(r10 - 60) = r2

LBB8_134:
     967:	*(u64 *)(r10 - 264) = r3
     968:	call 5
; if (tcp) {
     969:	r0 /= 1000000000
; entry->seen_non_syn |= !syn;
     970:	r1 = r0
     971:	r1 += 60
; return ktime_get_ns();
     972:	*(u32 *)(r10 - 64) = r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     973:	r1 = r0
; entry->lifetime = now + lifetime;
     974:	r1 <<= 32
     975:	r1 >>= 32
     976:	if r1 < 6 goto +1 <LBB8_136>
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     977:	*(u32 *)(r10 - 44) = r0

LBB8_136:
     978:	r1 = 1
     979:	*(u64 *)(r10 - 96) = r1
; if (*last_report + CT_REPORT_INTERVAL < now ||
     980:	r8 = *(u64 *)(r10 - 240)
     981:	r1 = *(u32 *)(r8 + 0)
     982:	*(u64 *)(r10 - 88) = r1
     983:	r9 = *(u32 *)(r10 - 184)
     984:	r1 = r8
; *last_report = now;
     985:	call 34
     986:	*(u32 *)(r10 - 132) = r0
; entry.tx_packets = 1;
     987:	r1 = 269496578
; entry.tx_bytes = skb->len;
     988:	*(u32 *)(r10 - 136) = r1
     989:	*(u32 *)(r10 - 128) = r6
; uint32_t hash = get_hash_recalc(skb);
     990:	*(u32 *)(r10 - 124) = r9
     991:	r6 = 0
; struct debug_msg msg = {
     992:	*(u32 *)(r10 - 120) = r6
     993:	r4 = r10
     994:	r4 += -136
     995:	r1 = r8
     996:	r2 = 0 ll
     998:	r3 = 4294967295 ll
; entry.tx_packets = 1;
    1000:	r5 = 20
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1001:	call 25
    1002:	r1 = *(u32 *)(r10 - 184)
    1003:	*(u32 *)(r10 - 52) = r1
    1004:	r2 = r10
    1005:	r2 += -176
    1006:	r3 = r10
    1007:	r3 += -96
; entry.src_sec_id = ct_state->src_sec_id;
    1008:	r8 = *(u64 *)(r10 - 264)
    1009:	r1 = r8
; entry.tx_packets = 1;
    1010:	r4 = 0
    1011:	call 2
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    1012:	r0 <<= 32
    1013:	r0 s>>= 32
    1014:	if r0 s> -1 goto +3 <LBB8_138>
    1015:	r9 = 4294967141 ll
    1017:	goto -823 <LBB8_56>

LBB8_138:
    1018:	r1 = 58
    1019:	*(u8 *)(r10 - 100) = r1
    1020:	r1 = *(u64 *)(r10 - 176)
; tuple->sport = type;
    1021:	*(u64 *)(r10 - 136) = r1
    1022:	r1 = *(u64 *)(r10 - 168)
    1023:	*(u64 *)(r10 - 128) = r1
    1024:	r1 = *(u64 *)(r10 - 160)
    1025:	*(u64 *)(r10 - 120) = r1
    1026:	r1 = *(u64 *)(r10 - 152)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
    1027:	*(u64 *)(r10 - 112) = r1
    1028:	r1 = *(u8 *)(r10 - 139)
    1029:	r1 |= 2
    1030:	*(u8 *)(r10 - 99) = r1
    1031:	r1 = *(u16 *)(r10 - 60)
    1032:	r1 |= 16
    1033:	*(u16 *)(r10 - 60) = r1
    1034:	*(u32 *)(r10 - 104) = r6
    1035:	r2 = r10
    1036:	r2 += -136
    1037:	r3 = r10
    1038:	r3 += -96
    1039:	r1 = r8
    1040:	r4 = 0
    1041:	call 2
    1042:	r0 <<= 32
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1043:	r9 = r0
    1044:	r9 s>>= 63
    1045:	r9 &= -155
    1046:	r0 s>>= 32
    1047:	r8 = *(u64 *)(r10 - 240)
    1048:	r6 = *(u64 *)(r10 - 328)
    1049:	if r0 s< 0 goto -854 <LBB8_57>

LBB8_139:
    1050:	r1 = r6
    1051:	r1 <<= 32
    1052:	r1 >>= 32
    1053:	if r1 > 1 goto +104 <LBB8_147>
    1054:	r7 <<= 32
    1055:	r7 s>>= 32
    1056:	if r7 s< 1 goto +101 <LBB8_147>
    1057:	r1 = 95142176846542 ll
    1059:	*(u64 *)(r10 - 208) = r1
    1060:	r1 = 244920237338078 ll
    1062:	*(u64 *)(r10 - 216) = r1
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1063:	r1 = 61374
    1064:	*(u64 *)(r10 - 232) = r1
    1065:	r1 = -264973711704064 ll
    1067:	*(u64 *)(r10 - 224) = r1
    1068:	r9 = *(u16 *)(r10 - 144)
    1069:	r1 = *(u64 *)(r10 - 280)
    1070:	*(u32 *)(r10 - 36) = r1
    1071:	r1 = *(u64 *)(r10 - 272)
    1072:	*(u32 *)(r10 - 40) = r1
    1073:	r1 = *(u64 *)(r10 - 288)
    1074:	*(u32 *)(r10 - 32) = r1
; uint32_t hash = get_hash_recalc(skb);
    1075:	r1 = *(u64 *)(r10 - 296)
    1076:	*(u32 *)(r10 - 28) = r1
; struct debug_msg msg = {
    1077:	*(u16 *)(r10 - 8) = r7
    1078:	r1 = *(u64 *)(r10 - 168)
    1079:	*(u64 *)(r10 - 16) = r1
    1080:	r1 = *(u64 *)(r10 - 176)
    1081:	*(u64 *)(r10 - 24) = r1
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1082:	r1 = *(u16 *)(r10 - 142)
    1083:	*(u16 *)(r10 - 6) = r1
    1084:	r1 = *(u8 *)(r10 - 140)
    1085:	*(u8 *)(r10 - 4) = r1
    1086:	r6 = 0
    1087:	*(u8 *)(r10 - 3) = r6
    1088:	*(u16 *)(r10 - 118) = r6
    1089:	r1 = *(u64 *)(r10 - 248)
    1090:	*(u32 *)(r10 - 116) = r1
    1091:	r1 = *(u64 *)(r10 - 32)
; struct debug_msg msg = {
    1092:	*(u64 *)(r10 - 128) = r1
    1093:	r1 = *(u64 *)(r10 - 40)
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1094:	*(u64 *)(r10 - 136) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1095:	*(u16 *)(r10 - 120) = r9
    1096:	call 5
    1097:	r0 /= 1000000000
    1098:	r0 += 720
    1099:	*(u32 *)(r10 - 112) = r0
    1100:	r2 = *(u64 *)(r10 - 352)
    1101:	r2 <<= 32
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1102:	r2 >>= 32
    1103:	if r2 == 0 goto +34 <LBB8_145>
    1104:	*(u64 *)(r10 - 264) = r9
    1105:	r9 = *(u32 *)(r8 + 0)
; uint32_t hash = get_hash_recalc(skb);
    1106:	r1 = r8
    1107:	r8 = r2
; struct debug_msg msg = {
    1108:	call 34
    1109:	r3 = r8
    1110:	*(u32 *)(r10 - 92) = r0
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1111:	r1 = 269484292
    1112:	*(u32 *)(r10 - 96) = r1
    1113:	r1 = 2
; struct debug_msg msg = {
    1114:	*(u64 *)(r10 - 80) = r1
    1115:	r1 = *(u64 *)(r10 - 328)
    1116:	*(u8 *)(r10 - 70) = r1
    1117:	*(u16 *)(r10 - 72) = r6
    1118:	*(u8 *)(r10 - 69) = r6
    1119:	r1 = 1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1120:	*(u32 *)(r10 - 68) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1121:	*(u32 *)(r10 - 88) = r9
    1122:	if r3 < r9 goto +1 <LBB8_144>
    1123:	r3 = r9

LBB8_144:
    1124:	*(u32 *)(r10 - 84) = r3
    1125:	r3 <<= 32
    1126:	r1 = 4294967295 ll
    1128:	r3 |= r1
    1129:	r4 = r10
    1130:	r4 += -96
; if ((entry = map_lookup_elem(map, tuple))) {
    1131:	r8 = *(u64 *)(r10 - 240)
    1132:	r1 = r8
    1133:	r2 = 0 ll
    1135:	r5 = 32
    1136:	call 25
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1137:	r9 = *(u64 *)(r10 - 264)

LBB8_145:
    1138:	r1 = *(u64 *)(r10 - 304)
    1139:	r1 &= 65535
; uint32_t hash = get_hash_recalc(skb);
    1140:	r2 = *(u64 *)(r10 - 312)
    1141:	r2 += r1
; struct debug_msg msg = {
    1142:	*(u16 *)(r10 - 96) = r7
    1143:	r7 &= 65535
    1144:	r5 = *(u64 *)(r10 - 360)
    1145:	r5 |= 2
    1146:	r5 &= 65535
    1147:	r1 = r8
    1148:	r6 = r2
    1149:	r3 = r9
    1150:	r4 = r7
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1151:	call 11
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1152:	r0 <<= 32
    1153:	r0 s>>= 32
    1154:	if r0 s> -1 goto +22 <LBB8_149>
    1155:	r9 = 4294967155 ll
    1157:	goto +103 <LBB8_156>

LBB8_147:
    1158:	r6 = *(u32 *)(r8 + 0)
; return !entry->rx_closing || !entry->tx_closing;
    1159:	r1 = 0
    1160:	*(u64 *)(r10 - 88) = r1
    1161:	*(u64 *)(r10 - 96) = r1
    1162:	r1 = 256
; if (ct_entry_alive(entry)) {
    1163:	*(u64 *)(r10 - 136) = r1
    1164:	r2 = r10
; if (tcp) {
    1165:	r2 += -136
    1166:	r1 = 0 ll
; entry->seen_non_syn |= !syn;
    1168:	call 1
    1169:	if r0 == 0 goto +126 <LBB8_163>
    1170:	r1 = *(u64 *)(r0 + 0)
    1171:	r1 += 1
    1172:	*(u64 *)(r0 + 0) = r1
    1173:	r1 = *(u64 *)(r0 + 8)
    1174:	r1 += r6
    1175:	*(u64 *)(r0 + 8) = r1
    1176:	goto +130 <LBB8_164>

LBB8_149:
    1177:	r2 = *(u64 *)(r10 - 320)
    1178:	r2 += 16
; if (entry->seen_non_syn)
    1179:	r3 = r10
    1180:	r3 += -96
    1181:	r1 = r8
    1182:	r4 = 2
; return ktime_get_ns();
    1183:	r5 = 0
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1184:	call 9
; entry->lifetime = now + lifetime;
    1185:	r9 = 4294967155 ll
; seen_flags |= *accumulated_flags;
    1187:	r0 <<= 32
    1188:	r0 s>>= 32
    1189:	if r0 s< 0 goto +71 <LBB8_156>
    1190:	r3 = r10
    1191:	r3 += -232
    1192:	r1 = r8
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1193:	r2 = 38
    1194:	r4 = 16
    1195:	r5 = 0
    1196:	call 9
    1197:	r0 <<= 32
    1198:	r0 s>>= 32
    1199:	if r0 s> 0 goto +61 <LBB8_156>
    1200:	r1 = *(u64 *)(r10 - 304)
    1201:	if r1 == 0 goto +21 <LBB8_153>
; *accumulated_flags = seen_flags;
    1202:	r1 = r10
; *last_report = now;
    1203:	r1 += -40
    1204:	r3 = r10
; ct_state->rev_nat_index = entry->rev_nat_index;
    1205:	r3 += -232
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1206:	r2 = 16
    1207:	r4 = 16
    1208:	r5 = 0
    1209:	call 28
    1210:	r5 = *(u64 *)(r10 - 360)
    1211:	r5 |= 16
    1212:	r5 &= 65535
; skb->cb[CB_NAT46_STATE] = NAT46;
    1213:	r1 = r8
    1214:	r2 = r6
    1215:	r3 = 0
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1216:	r4 = r0
    1217:	call 11
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1218:	r9 = 4294967142 ll
    1220:	r0 <<= 32
    1221:	r0 s>>= 32
    1222:	if r0 s< 0 goto +38 <LBB8_156>

LBB8_153:
; switch (action) {
    1223:	r1 = r8
    1224:	r8 = *(u32 *)(r1 + 0)
    1225:	call 34
    1226:	*(u32 *)(r10 - 92) = r0
; ret = entry->rx_closing + entry->tx_closing;
    1227:	r1 = 269486339
    1228:	*(u32 *)(r10 - 96) = r1
    1229:	*(u32 *)(r10 - 80) = r7
    1230:	*(u32 *)(r10 - 88) = r8
    1231:	if r8 < 128 goto +1 <LBB8_155>
    1232:	r8 = 128

LBB8_155:
; if (unlikely(ret >= 1)) {
    1233:	*(u32 *)(r10 - 84) = r8
    1234:	r8 <<= 32
; entry->tx_closing = 0;
    1235:	r1 = 4294967295 ll
    1237:	r8 |= r1
    1238:	r1 = 0
; if (tcp) {
    1239:	*(u32 *)(r10 - 76) = r1
    1240:	r4 = r10
    1241:	r4 += -96
; entry->seen_non_syn |= !syn;
    1242:	r1 = *(u64 *)(r10 - 240)
    1243:	r2 = 0 ll
    1245:	r3 = r8
    1246:	r8 = r1
    1247:	r5 = 24
    1248:	call 25
    1249:	r2 = r10
    1250:	r2 += -24
    1251:	r3 = r10
    1252:	r3 += -136
; if (entry->seen_non_syn)
    1253:	r1 = 0 ll
    1255:	r4 = 0
    1256:	call 2
; return ktime_get_ns();
    1257:	r9 = r0
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1258:	r9 <<= 32
; entry->lifetime = now + lifetime;
    1259:	r9 s>>= 63
    1260:	r9 &= -161

LBB8_156:
; seen_flags |= *accumulated_flags;
    1261:	r1 = r9
    1262:	r1 <<= 32
    1263:	r1 >>= 32
    1264:	r2 = 1
    1265:	if r1 == 2 goto +1 <LBB8_158>
    1266:	r2 = 0

LBB8_158:
    1267:	r1 >>= 31
    1268:	r1 |= r2
    1269:	if r1 != 0 goto +22 <LBB8_161>
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1270:	r3 = r10
    1271:	r3 += -216
    1272:	r1 = r8
    1273:	r2 = 6
    1274:	r4 = 6
    1275:	r5 = 0
    1276:	call 9
    1277:	r9 = 4294967155 ll
    1279:	r0 <<= 32
; *accumulated_flags = seen_flags;
    1280:	r0 s>>= 32
; *last_report = now;
    1281:	if r0 s< 0 goto +10 <LBB8_161>
    1282:	r3 = r10
    1283:	r3 += -208
; tmp = tuple->sport;
    1284:	r1 = r8
; tuple->sport = tuple->dport;
    1285:	r2 = 0
    1286:	r4 = 6
; tmp = tuple->sport;
    1287:	r5 = 0
; tuple->sport = tuple->dport;
    1288:	call 9
    1289:	r0 <<= 32
; dst->p1 = src->p1;
    1290:	r0 s>>= 32
    1291:	if r0 s> -1 goto +1 <LBB8_162>

LBB8_161:
    1292:	goto -1097 <LBB8_57>

LBB8_162:
; dst->p2 = src->p2;
    1293:	r1 = 1
    1294:	*(u32 *)(r8 + 52) = r1
    1295:	goto +53 <LBB8_169>

LBB8_163:
    1296:	*(u64 *)(r10 - 88) = r6
; dst->p3 = src->p3;
    1297:	r1 = 1
    1298:	*(u64 *)(r10 - 96) = r1
    1299:	r2 = r10
    1300:	r2 += -136
; dst->p4 = src->p4;
    1301:	r3 = r10
    1302:	r3 += -96
    1303:	r1 = 0 ll
; dst->p1 = src->p1;
    1305:	r4 = 0
; tuple->dport = tmp;
    1306:	call 2

LBB8_164:
    1307:	r2 = *(u64 *)(r10 - 352)
; if (tuple->flags & TUPLE_F_IN)
    1308:	r2 <<= 32
; tuple->flags |= TUPLE_F_IN;
    1309:	r2 >>= 32
    1310:	if r2 == 0 goto +35 <LBB8_168>
; if (tuple->flags & TUPLE_F_IN)
    1311:	r6 = *(u32 *)(r8 + 0)
    1312:	r1 = r8
    1313:	r7 = r2
    1314:	call 34
    1315:	r3 = r7
    1316:	*(u32 *)(r10 - 92) = r0
    1317:	r1 = 269484036
    1318:	*(u32 *)(r10 - 96) = r1
    1319:	r1 = *(u64 *)(r10 - 248)
; if ((entry = map_lookup_elem(map, tuple))) {
    1320:	*(u32 *)(r10 - 80) = r1
    1321:	r1 = 2
    1322:	*(u32 *)(r10 - 76) = r1
    1323:	r1 = 4112
    1324:	*(u16 *)(r10 - 72) = r1
    1325:	r1 = *(u64 *)(r10 - 328)
    1326:	*(u8 *)(r10 - 70) = r1
    1327:	r1 = 0
    1328:	*(u8 *)(r10 - 69) = r1
    1329:	r1 = *(u64 *)(r10 - 256)
    1330:	*(u32 *)(r10 - 68) = r1
    1331:	*(u32 *)(r10 - 88) = r6
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1332:	if r3 < r6 goto +1 <LBB8_167>
    1333:	r3 = r6

LBB8_167:
    1334:	*(u32 *)(r10 - 84) = r3
; uint32_t hash = get_hash_recalc(skb);
    1335:	r3 <<= 32
    1336:	r1 = 4294967295 ll
; struct debug_msg msg = {
    1338:	r3 |= r1
    1339:	r4 = r10
    1340:	r4 += -96
    1341:	r1 = r8
    1342:	r2 = 0 ll
    1344:	r5 = 32
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1345:	call 25

LBB8_168:
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1346:	r9 = 0
    1347:	r1 = *(u32 *)(r8 + 52)
    1348:	if r1 == 0 goto -1153 <LBB8_57>

LBB8_169:
    1349:	r2 = 0
    1350:	call 23
    1351:	r9 = r0
    1352:	goto -1157 <LBB8_57>

LBB8_170:
; return !entry->rx_closing || !entry->tx_closing;
    1353:	*(u64 *)(r10 - 88) = r6
    1354:	r1 = 1
    1355:	*(u64 *)(r10 - 96) = r1
    1356:	r2 = r10
; if (ct_entry_alive(entry)) {
    1357:	r2 += -136
    1358:	r3 = r10
; if (tcp) {
    1359:	r3 += -96
    1360:	r1 = 0 ll
; entry->seen_non_syn |= !syn;
    1362:	r4 = 0
    1363:	call 2

LBB8_171:
    1364:	r1 = r8
    1365:	r2 = 0 ll
    1367:	r3 = 1
    1368:	call 12
    1369:	r9 = 2

LBB8_172:
    1370:	r0 = r9
    1371:	exit

LBB8_173:
    1372:	r1 = *(u64 *)(r10 - 344)
; if (entry->seen_non_syn)
    1373:	*(u16 *)(r10 - 24) = r1
    1374:	r1 = r8
    1375:	call 34
    1376:	*(u32 *)(r10 - 92) = r0
; return ktime_get_ns();
    1377:	r1 = 269490690
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1378:	*(u32 *)(r10 - 96) = r1
; entry->lifetime = now + lifetime;
    1379:	*(u32 *)(r10 - 88) = r7
    1380:	r1 = 0
; seen_flags |= *accumulated_flags;
    1381:	*(u32 *)(r10 - 84) = r1
    1382:	*(u32 *)(r10 - 80) = r1
    1383:	r4 = r10
    1384:	r4 += -96
    1385:	r1 = r8
    1386:	r2 = 0 ll
    1388:	r3 = 4294967295 ll
    1390:	r5 = 20
    1391:	call 25
    1392:	r2 = r10
    1393:	r2 += -24
    1394:	r1 = 0 ll
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1396:	call 1
; *accumulated_flags = seen_flags;
    1397:	r9 = 0
; *last_report = now;
    1398:	*(u64 *)(r10 - 336) = r0
    1399:	if r0 == 0 goto +192 <LBB8_201>
; ct_state->rev_nat_index = entry->rev_nat_index;
    1400:	r7 = *(u64 *)(r10 - 336)
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1401:	r8 = *(u8 *)(r7 + 17)
    1402:	r8 <<= 8
    1403:	r1 = *(u8 *)(r7 + 16)
    1404:	r8 |= r1
    1405:	r1 = *(u8 *)(r7 + 14)
    1406:	*(u64 *)(r10 - 344) = r1
    1407:	r6 = *(u8 *)(r7 + 15)
; skb->cb[CB_NAT46_STATE] = NAT46;
    1408:	r1 = *(u8 *)(r7 + 12)
    1409:	*(u64 *)(r10 - 368) = r1
    1410:	r9 = *(u8 *)(r7 + 13)
    1411:	r1 = *(u64 *)(r10 - 240)
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1412:	call 34
    1413:	*(u32 *)(r10 - 92) = r0
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1414:	r1 = 269490946
    1415:	*(u32 *)(r10 - 96) = r1
    1416:	*(u32 *)(r10 - 84) = r8
    1417:	r1 = 0
    1418:	*(u32 *)(r10 - 80) = r1
    1419:	r9 <<= 8
; switch (action) {
    1420:	r1 = *(u64 *)(r10 - 368)
    1421:	r9 |= r1
    1422:	r6 <<= 8
    1423:	r1 = *(u64 *)(r10 - 344)
; ret = entry->rx_closing + entry->tx_closing;
    1424:	r6 |= r1
    1425:	r6 <<= 16
    1426:	r6 |= r9
    1427:	*(u32 *)(r10 - 88) = r6
    1428:	r4 = r10
    1429:	r4 += -96
; if (unlikely(ret >= 1)) {
    1430:	r1 = *(u64 *)(r10 - 240)
    1431:	r2 = 0 ll
; entry->tx_closing = 0;
    1433:	r3 = 4294967295 ll
    1435:	r5 = 20
; if (tcp) {
    1436:	call 25
    1437:	r1 = *(u8 *)(r7 + 16)
    1438:	r8 = *(u8 *)(r7 + 17)
; entry->seen_non_syn |= !syn;
    1439:	r8 <<= 8
    1440:	r8 |= r1
    1441:	if r8 == 0 goto +90 <LBB8_196>
    1442:	r9 = 4294967154 ll
    1444:	r1 = *(u8 *)(r10 - 140)
    1445:	if r1 s> 16 goto +19 <LBB8_180>
    1446:	if r1 == 1 goto +75 <LBB8_192>
    1447:	if r1 == 6 goto +19 <LBB8_182>
    1448:	goto +74 <LBB8_193>

LBB8_178:
    1449:	r8 = *(u64 *)(r10 - 336)
; if (entry->seen_non_syn)
    1450:	*(u8 *)(r10 - 130) = r7
    1451:	*(u16 *)(r10 - 132) = r7
    1452:	r2 = r10
    1453:	r2 += -136
; return ktime_get_ns();
    1454:	r1 = 0 ll
; entry->lifetime = now + lifetime;
    1456:	call 1
    1457:	if r0 == 0 goto +146 <LBB8_205>
; seen_flags |= *accumulated_flags;
    1458:	r1 = 1
    1459:	lock *(u64 *)(r0 + 8) += r1
    1460:	r1 = *(u64 *)(r10 - 240)
    1461:	r1 = *(u32 *)(r1 + 0)
    1462:	lock *(u64 *)(r0 + 16) += r1
    1463:	r7 = 0
    1464:	goto -533 <LBB8_125>

LBB8_180:
    1465:	if r1 == 58 goto +56 <LBB8_192>
    1466:	if r1 != 17 goto +56 <LBB8_193>

LBB8_182:
    1467:	r3 = r10
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1468:	r3 += -136
    1469:	r1 = *(u64 *)(r10 - 240)
    1470:	r2 = *(u64 *)(r10 - 312)
    1471:	r4 = 2
    1472:	call 26
    1473:	r9 = r0
    1474:	r1 = r9
    1475:	r1 <<= 32
    1476:	r1 >>= 32
    1477:	r2 = 1
; *accumulated_flags = seen_flags;
    1478:	if r1 == 2 goto +1 <LBB8_184>
; *last_report = now;
    1479:	r2 = 0

LBB8_184:
    1480:	r1 >>= 31
    1481:	r1 |= r2
    1482:	if r1 != 0 goto +38 <LBB8_191>
; if (dir == CT_INGRESS)
    1483:	r3 = *(u16 *)(r10 - 136)
    1484:	if r3 == r8 goto +37 <LBB8_192>
    1485:	r1 = *(u64 *)(r10 - 304)
; return !entry->rx_closing || !entry->tx_closing;
    1486:	r1 &= 65535
; if (ct_entry_alive(entry))
    1487:	r2 = *(u64 *)(r10 - 312)
; return ktime_get_ns();
    1488:	r2 += r1
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1489:	*(u16 *)(r10 - 96) = r8
; entry->lifetime = now + lifetime;
    1490:	r5 = *(u64 *)(r10 - 360)
    1491:	r5 |= 2
    1492:	r5 &= 65535
; seen_flags |= *accumulated_flags;
    1493:	r1 = *(u64 *)(r10 - 240)
    1494:	r4 = r8
    1495:	call 11
    1496:	r9 = 4294967142 ll
    1498:	r0 <<= 32
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1499:	r0 s>>= 32
    1500:	if r0 s< 0 goto +11 <LBB8_188>
    1501:	r3 = r10
    1502:	r3 += -96
    1503:	r1 = *(u64 *)(r10 - 240)
    1504:	r2 = *(u64 *)(r10 - 312)
    1505:	r4 = 2
    1506:	r5 = 0
    1507:	call 9
; *accumulated_flags = seen_flags;
    1508:	r9 = r0
; *last_report = now;
    1509:	r9 <<= 32
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1510:	r9 s>>= 63
    1511:	r9 &= -141

LBB8_188:
    1512:	r1 = r9
    1513:	r1 <<= 32
    1514:	r1 >>= 32
    1515:	r2 = 1
; if (dir == CT_INGRESS)
    1516:	if r1 == 2 goto +1 <LBB8_190>
    1517:	r2 = 0

LBB8_190:
    1518:	r1 >>= 31
; return !entry->rx_closing || !entry->tx_closing;
    1519:	r1 |= r2
; if (ct_entry_alive(entry))
    1520:	if r1 == 0 goto +1 <LBB8_192>

LBB8_191:
; return ktime_get_ns();
    1521:	goto +1 <LBB8_193>

LBB8_192:
    1522:	r9 = 0

LBB8_193:
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1523:	r1 = r9
; entry->lifetime = now + lifetime;
    1524:	r1 <<= 32
    1525:	r1 >>= 32
    1526:	r2 = 1
; seen_flags |= *accumulated_flags;
    1527:	if r1 == 2 goto +1 <LBB8_195>
    1528:	r2 = 0

LBB8_195:
    1529:	r1 >>= 31
    1530:	r1 |= r2
    1531:	if r1 != 0 goto +60 <LBB8_201>

LBB8_196:
    1532:	r3 = r10
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1533:	r3 += -96
    1534:	r1 = *(u64 *)(r10 - 240)
    1535:	r2 = 22
    1536:	r4 = 16
    1537:	call 26
    1538:	r9 = 4294967162 ll
    1540:	r0 <<= 32
    1541:	r0 s>>= 32
; *accumulated_flags = seen_flags;
    1542:	if r0 s< 0 goto +49 <LBB8_201>
; *last_report = now;
    1543:	r2 = *(u64 *)(r10 - 336)
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
    1544:	r1 = *(u32 *)(r2 + 0)
    1545:	*(u32 *)(r10 - 136) = r1
    1546:	r1 = *(u32 *)(r2 + 4)
; uint32_t hash = get_hash_recalc(skb);
    1547:	*(u32 *)(r10 - 132) = r1
    1548:	r1 = *(u32 *)(r2 + 8)
; struct debug_msg msg = {
    1549:	*(u32 *)(r10 - 128) = r1
    1550:	r1 = *(u32 *)(r2 + 12)
    1551:	*(u32 *)(r10 - 124) = r1
    1552:	r3 = r10
    1553:	r3 += -136
    1554:	r1 = *(u64 *)(r10 - 240)
    1555:	r2 = 22
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
    1556:	r4 = 16
    1557:	r5 = 0
; struct debug_msg msg = {
    1558:	call 9
    1559:	r0 <<= 32
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    1560:	r0 >>= 32
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1561:	r1 = 1
    1562:	if r0 == 2 goto +1 <LBB8_199>
    1563:	r1 = 0

LBB8_199:
    1564:	r0 >>= 31
    1565:	r0 |= r1
    1566:	r9 = 4294967155 ll
    1568:	if r0 != 0 goto +23 <LBB8_201>
; if (conn_is_dns(tuple->dport))
    1569:	r1 = r10
    1570:	r1 += -96
    1571:	r3 = r10
    1572:	r3 += -136
    1573:	r2 = 16
    1574:	r4 = 16
    1575:	r5 = 0
    1576:	call 28
    1577:	r1 = *(u64 *)(r10 - 304)
    1578:	r1 &= 65535
    1579:	r2 = *(u64 *)(r10 - 312)
; void *data_end = (void *) (long) skb->data_end;
    1580:	r2 += r1
; void *data = (void *) (long) skb->data;
    1581:	r5 = *(u64 *)(r10 - 360)
; if (data + ETH_HLEN + l3_len > data_end)
    1582:	r5 |= 16
    1583:	r5 &= 65535
    1584:	r1 = *(u64 *)(r10 - 240)
    1585:	r3 = 0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1586:	r4 = r0
    1587:	call 11
    1588:	r9 = r0
    1589:	r9 <<= 32
; addr->p4 &= GET_PREFIX(prefix);
    1590:	r9 s>>= 63
; addr->p3 &= GET_PREFIX(prefix);
    1591:	r9 &= -154

LBB8_201:
    1592:	r1 = r9
    1593:	r1 <<= 32
    1594:	r1 >>= 32
    1595:	r2 = 1
    1596:	if r1 == 2 goto +1 <LBB8_203>
; .ip6 = *addr,
    1597:	r2 = 0

LBB8_203:
    1598:	r1 >>= 31
    1599:	r1 |= r2
    1600:	r8 = *(u64 *)(r10 - 240)
    1601:	if r1 != 0 goto -1406 <LBB8_57>
    1602:	r6 = *(u16 *)(r10 - 144)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1603:	goto -714 <LBB8_122>

LBB8_205:
; return map_lookup_elem(map, &key);
    1604:	*(u16 *)(r10 - 132) = r6
    1605:	r7 = 0
    1606:	*(u32 *)(r10 - 136) = r7
    1607:	*(u8 *)(r10 - 130) = r8
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1608:	r2 = r10
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1609:	r2 += -136
    1610:	r1 = 0 ll
; .ip6 = *addr,
    1612:	call 1
; addr->p4 &= GET_PREFIX(prefix);
    1613:	r8 = r0
; addr->p3 &= GET_PREFIX(prefix);
    1614:	if r8 == 0 goto +5 <LBB8_207>
    1615:	r1 = 1
    1616:	lock *(u64 *)(r8 + 8) += r1
    1617:	r1 = *(u64 *)(r10 - 240)
    1618:	r1 = *(u32 *)(r1 + 0)
    1619:	goto -690 <LBB8_124>

LBB8_207:
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1620:	r1 = *(u64 *)(r10 - 240)
; return map_lookup_elem(map, &key);
    1621:	r1 = *(u32 *)(r1 + 56)
    1622:	r6 = *(u64 *)(r10 - 328)
    1623:	if r1 == 0 goto +1 <LBB8_208>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1624:	goto -692 <LBB8_126>

LBB8_208:
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1625:	r8 = *(u64 *)(r10 - 240)
    1626:	r1 = r8
    1627:	call 34
; .ip6 = *addr,
    1628:	*(u32 *)(r10 - 92) = r0
    1629:	r1 = 269485314
; addr->p4 &= GET_PREFIX(prefix);
    1630:	*(u32 *)(r10 - 96) = r1
; addr->p3 &= GET_PREFIX(prefix);
    1631:	r1 = *(u64 *)(r10 - 248)
    1632:	*(u32 *)(r10 - 88) = r1
    1633:	r1 = 2
    1634:	*(u32 *)(r10 - 84) = r1
    1635:	r1 = 0
    1636:	*(u32 *)(r10 - 80) = r1
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1637:	r4 = r10
; return map_lookup_elem(map, &key);
    1638:	r4 += -96
    1639:	r1 = r8
    1640:	r2 = 0 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1642:	r3 = 4294967295 ll
    1644:	r5 = 20
; .ip6 = *addr,
    1645:	call 25
; addr->p4 &= GET_PREFIX(prefix);
    1646:	r7 = 4294967163 ll
; addr->p3 &= GET_PREFIX(prefix);
    1648:	r1 = r6
    1649:	r1 |= 1
    1650:	if r1 == 3 goto -717 <LBB8_127>
    1651:	r9 = 4294967163 ll
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1653:	if r6 != 1 goto -1458 <LBB8_57>
; return map_lookup_elem(map, &key);
    1654:	r1 = 0 ll
    1656:	r2 = *(u8 *)(r10 - 140)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1657:	if r2 == 6 goto +2 <LBB8_212>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1658:	r1 = 0 ll

LBB8_212:
    1660:	r2 = r10
; .ip6 = *addr,
    1661:	r2 += -176
    1662:	call 3
; addr->p4 &= GET_PREFIX(prefix);
    1663:	r7 = r0
; addr->p3 &= GET_PREFIX(prefix);
    1664:	r7 <<= 32
    1665:	r7 s>>= 32
    1666:	r8 = *(u64 *)(r10 - 240)
    1667:	if r7 s> -1 goto -1472 <LBB8_57>
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1668:	r1 = r8
; return map_lookup_elem(map, &key);
    1669:	call 34
    1670:	*(u32 *)(r10 - 92) = r0
    1671:	r1 = 269488642
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1672:	*(u32 *)(r10 - 96) = r1
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1673:	r1 = 3
    1674:	*(u32 *)(r10 - 88) = r1
    1675:	*(u32 *)(r10 - 84) = r7
; .ip6 = *addr,
    1676:	r1 = 0
; addr->p4 &= GET_PREFIX(prefix);
    1677:	*(u32 *)(r10 - 80) = r1
; addr->p3 &= GET_PREFIX(prefix);
    1678:	r4 = r10
    1679:	r4 += -96
    1680:	r1 = r8
    1681:	r2 = 0 ll
; return map_lookup_elem(map, &key);
    1683:	r3 = 4294967295 ll
    1685:	r5 = 20
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1686:	call 25
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1687:	goto -1492 <LBB8_57>
Disassembly of section 2/11:
tail_ipv4_policy:
; {
       0:	r9 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r6 = *(u32 *)(r9 + 48)
       2:	r1 = *(u32 *)(r9 + 52)
       3:	*(u64 *)(r10 - 160) = r1
       4:	r1 = 0
; struct lb6_key key = {};
       5:	*(u16 *)(r10 - 100) = r1
       6:	*(u32 *)(r10 - 104) = r1
       7:	*(u64 *)(r10 - 112) = r1
       8:	*(u64 *)(r10 - 120) = r1
       9:	*(u64 *)(r10 - 128) = r1
; tmp = a->p1 - b->p1;
      10:	*(u64 *)(r10 - 136) = r1
; if (!tmp)
      11:	r7 = 4294967162 ll
      13:	r2 = *(u32 *)(r9 + 80)
; tmp = a->p2 - b->p2;
      14:	r8 = *(u32 *)(r9 + 76)
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r3 = r8
      16:	r3 += 34
      17:	if r3 > r2 goto +1481 <LBB9_191>
; tmp = a->p1 - b->p1;
      18:	*(u32 *)(r9 + 56) = r1
; if (!tmp)
      19:	r1 = *(u8 *)(r8 + 23)
      20:	*(u8 *)(r10 - 100) = r1
      21:	r2 = *(u32 *)(r9 + 44)
; tmp = a->p2 - b->p2;
      22:	*(u32 *)(r10 - 40) = r2
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	r2 = *(u32 *)(r10 - 40)
      24:	r2 &= 1
      25:	if r2 == 0 goto +20 <LBB9_3>
; tmp = a->p1 - b->p1;
      26:	r7 = *(u32 *)(r10 - 40)
; if (!tmp) {
      27:	r1 = r9
; tmp = a->p2 - b->p2;
      28:	call 34
; if (!tmp) {
      29:	*(u32 *)(r10 - 92) = r0
; tmp = a->p3 - b->p3;
      30:	r1 = 269496834
; if (!tmp)
      31:	*(u32 *)(r10 - 96) = r1
; tmp = a->p4 - b->p4;
      32:	*(u32 *)(r10 - 88) = r7
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r1 = 0
      34:	*(u32 *)(r10 - 84) = r1
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	*(u32 *)(r10 - 80) = r1
      36:	r4 = r10
; dst->p1 = src->p1;
      37:	r4 += -96
      38:	r1 = r9
; dst->p2 = src->p2;
      39:	r2 = 0 ll
; dst->p3 = src->p3;
      41:	r3 = 4294967295 ll
; dst->p4 = src->p4;
      43:	r5 = 20
      44:	call 25
; dst->p1 = src->p1;
      45:	r1 = *(u8 *)(r10 - 100)

LBB9_3:
      46:	r4 = *(u32 *)(r10 - 40)
; dst->p2 = src->p2;
      47:	r3 = *(u32 *)(r8 + 30)
      48:	*(u32 *)(r10 - 112) = r3
; dst->p3 = src->p3;
      49:	r2 = *(u32 *)(r8 + 26)
      50:	*(u32 *)(r10 - 108) = r2
; dst->p4 = src->p4;
      51:	if r1 == 58 goto +266 <LBB9_8>
      52:	r2 = *(u8 *)(r8 + 14)
      53:	r2 <<= 2
      54:	r2 &= 60
; __u8 nh = *nexthdr;
      55:	r2 += 14
; switch (nh) {
      56:	*(u64 *)(r10 - 232) = r3
      57:	*(u64 *)(r10 - 192) = r2
      58:	*(u64 *)(r10 - 216) = r4
      59:	if r1 == 17 goto +266 <LBB9_7>
      60:	if r1 != 6 goto +292 <LBB9_9>
      61:	r1 = *(u16 *)(r8 + 20)
      62:	*(u64 *)(r10 - 200) = r1
      63:	r8 = 0
      64:	*(u8 *)(r10 - 99) = r8
      65:	*(u16 *)(r10 - 40) = r8
      66:	r2 += 12
      67:	r3 = r10
      68:	r3 += -40
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r1 = r9
      70:	r4 = 2
      71:	call 26
      72:	r7 = 4294967161 ll
      74:	r0 <<= 32
      75:	r0 s>>= 32
      76:	if r0 s< 0 goto +1422 <LBB9_191>
      77:	*(u64 *)(r10 - 184) = r6
      78:	r6 = *(u8 *)(r10 - 40)
      79:	r3 = r10
; nh = opthdr.nexthdr;
      80:	r3 += -104
; if (nh == NEXTHDR_AUTH)
      81:	r1 = r9
      82:	r2 = *(u64 *)(r10 - 192)
      83:	r4 = 4
      84:	call 26
      85:	r2 = 16
      86:	r1 = 1
; switch (nh) {
      87:	*(u64 *)(r10 - 208) = r1
      88:	r1 = 0 ll
      90:	*(u64 *)(r10 - 176) = r1
      91:	r1 = r10
      92:	r1 += -40
      93:	r6 &= 1
      94:	r6 += 1
      95:	*(u64 *)(r10 - 224) = r6
      96:	r6 = *(u64 *)(r10 - 184)
      97:	r0 <<= 32
      98:	r0 s>>= 32
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	if r0 s< 0 goto +1399 <LBB9_191>

LBB9_28:
     100:	*(u64 *)(r10 - 248) = r2
     101:	*(u64 *)(r10 - 256) = r8
     102:	*(u64 *)(r10 - 184) = r6
     103:	r7 = *(u16 *)(r10 - 104)
     104:	r8 = *(u16 *)(r10 - 102)
     105:	*(u64 *)(r10 - 168) = r9
     106:	r9 = *(u32 *)(r10 - 112)
     107:	r6 = *(u32 *)(r10 - 108)
     108:	r1 = *(u64 *)(r10 - 168)
     109:	call 34
; nh = opthdr.nexthdr;
     110:	*(u32 *)(r10 - 92) = r0
; if (nh == NEXTHDR_AUTH)
     111:	r1 = 269495298
     112:	*(u32 *)(r10 - 96) = r1
     113:	*(u32 *)(r10 - 88) = r6
     114:	*(u32 *)(r10 - 84) = r9
     115:	r9 = *(u64 *)(r10 - 168)
     116:	r8 = be32 r8
     117:	r1 = 4294901760 ll
     119:	r8 &= r1
     120:	r7 = be16 r7
     121:	r8 |= r7
     122:	*(u32 *)(r10 - 80) = r8
     123:	r4 = r10
     124:	r4 += -96
     125:	r1 = r9
     126:	r2 = 0 ll
     128:	r3 = 4294967295 ll
     130:	r5 = 20
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	call 25
     132:	r6 = *(u8 *)(r10 - 99)
     133:	r7 = *(u8 *)(r10 - 100)
     134:	r1 = r9
     135:	call 34
     136:	*(u32 *)(r10 - 92) = r0
     137:	r1 = 269495554
     138:	*(u32 *)(r10 - 96) = r1
     139:	r7 <<= 8
     140:	r7 |= r6
     141:	*(u32 *)(r10 - 88) = r7
; nh = opthdr.nexthdr;
     142:	r1 = 0
; if (nh == NEXTHDR_AUTH)
     143:	*(u32 *)(r10 - 84) = r1
     144:	*(u32 *)(r10 - 80) = r1
     145:	r4 = r10
     146:	r4 += -96
     147:	r1 = r9
     148:	r2 = 0 ll
; switch (nh) {
     150:	r3 = 4294967295 ll
     152:	r5 = 20
     153:	call 25
     154:	r6 = *(u8 *)(r10 - 39)
     155:	r1 = *(u8 *)(r10 - 40)
     156:	*(u64 *)(r10 - 264) = r1
     157:	r2 = r10
     158:	r2 += -112
     159:	r8 = *(u64 *)(r10 - 176)
     160:	r1 = r8
     161:	call 1
     162:	r7 = r0
; *nexthdr = nh;
     163:	if r7 == 0 goto +234 <LBB9_53>
; dst->p1 = src->p1;
     164:	*(u64 *)(r10 - 176) = r6
     165:	r6 = *(u16 *)(r7 + 38)
; dst->p2 = src->p2;
     166:	r8 = *(u32 *)(r7 + 32)
     167:	r1 = r9
; dst->p3 = src->p3;
     168:	call 34
     169:	*(u32 *)(r10 - 92) = r0
; dst->p4 = src->p4;
     170:	r1 = 269486082
     171:	*(u32 *)(r10 - 96) = r1
     172:	*(u32 *)(r10 - 88) = r8
     173:	r8 = 0
     174:	*(u32 *)(r10 - 84) = r6
; switch (nexthdr) {
     175:	*(u32 *)(r10 - 80) = r8
     176:	r4 = r10
     177:	r4 += -96
     178:	r1 = r9
     179:	r2 = 0 ll
     181:	r3 = 4294967295 ll
     183:	r5 = 20
     184:	call 25
; }
     185:	r1 = *(u16 *)(r7 + 36)
     186:	r2 = r1
; switch (nexthdr) {
     187:	r2 &= 3
     188:	r6 = *(u64 *)(r10 - 224)
     189:	if r2 == 3 goto +43 <LBB9_36>
     190:	r9 = 60
     191:	r2 = *(u64 *)(r10 - 208)
     192:	r2 &= 1
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	if r2 == 0 goto +16 <LBB9_33>
     194:	r2 = *(u64 *)(r10 - 264)
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r2 ^= 1
     196:	r2 &= 255
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r3 = r1
     198:	r3 >>= 4
     199:	r3 |= r2
     200:	r2 = r3
     201:	r2 <<= 4
     202:	r2 &= 16
     203:	r1 &= 65519
; if (IS_ERR(ret))
     204:	r2 |= r1
     205:	*(u16 *)(r7 + 36) = r2
     206:	r3 &= 1
     207:	r9 = 60
     208:	if r3 == 0 goto +1 <LBB9_33>
     209:	r9 = 21600

LBB9_33:
     210:	call 5
     211:	r0 /= 1000000000
     212:	r9 += r0
     213:	*(u32 *)(r7 + 32) = r9
; if (IS_ERR(ret)) {
     214:	r2 = *(u8 *)(r7 + 43)
     215:	r1 = r2
     216:	r3 = *(u64 *)(r10 - 176)
     217:	r1 |= r3
     218:	r3 = r1
     219:	r3 &= 255
     220:	r9 = *(u64 *)(r10 - 168)
     221:	if r2 != r3 goto +8 <LBB9_35>
     222:	r2 = *(u32 *)(r7 + 52)
     223:	r2 += 5
     224:	r3 = r0
     225:	r3 <<= 32
     226:	r3 >>= 32
     227:	r2 <<= 32
; if (ret == DROP_UNKNOWN_L4)
     228:	r2 >>= 32
     229:	if r2 >= r3 goto +3 <LBB9_36>

LBB9_35:
     230:	*(u8 *)(r7 + 43) = r1
     231:	*(u32 *)(r7 + 52) = r0
     232:	r8 = 128

LBB9_36:
     233:	r1 = *(u16 *)(r7 + 38)
     234:	*(u16 *)(r10 - 136) = r1
     235:	r1 = *(u16 *)(r10 - 134)
     236:	r1 &= 65534
     237:	r2 = *(u16 *)(r7 + 36)
     238:	r3 = r2
     239:	r3 >>= 3
     240:	r3 &= 1
; if (key->dport) {
     241:	r1 |= r3
     242:	*(u16 *)(r10 - 134) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r1 = *(u16 *)(r7 + 40)
; uint32_t hash = get_hash_recalc(skb);
     244:	*(u16 *)(r10 - 116) = r1
     245:	r2 &= 4
; struct debug_msg msg = {
     246:	if r2 == 0 goto +4 <LBB9_39>
     247:	r1 = *(u32 *)(r9 + 60)
     248:	if r1 != 0 goto +2 <LBB9_39>
     249:	r1 = 2
     250:	*(u32 *)(r9 + 60) = r1

LBB9_39:
     251:	r1 = 1
     252:	lock *(u64 *)(r7 + 0) += r1
     253:	r1 = *(u32 *)(r9 + 0)
     254:	lock *(u64 *)(r7 + 8) += r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	if r6 == 2 goto +328 <LBB9_48>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	*(u64 *)(r10 - 240) = r8
     257:	r6 <<= 32
     258:	r6 >>= 32
     259:	if r6 != 1 goto +353 <LBB9_52>
     260:	r1 = *(u16 *)(r7 + 36)
     261:	r2 = r1
     262:	r2 &= 1
     263:	r3 = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	r3 >>= 1
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	r3 &= 1
     266:	r3 = -r3
     267:	if r2 == r3 goto +345 <LBB9_52>
; if (svc && svc->count != 0)
     268:	r2 = r1
     269:	r2 &= 65532
     270:	*(u16 *)(r7 + 36) = r2
     271:	r8 = 60
     272:	r2 = *(u64 *)(r10 - 208)
     273:	r2 &= 1
; key->dport = 0;
     274:	if r2 == 0 goto +16 <LBB9_45>
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r3 = *(u64 *)(r10 - 264)
; uint32_t hash = get_hash_recalc(skb);
     276:	r3 ^= 1
     277:	r3 &= 255
; struct debug_msg msg = {
     278:	r2 = r1
     279:	r2 >>= 4
     280:	r2 |= r3
     281:	r3 = r2
     282:	r3 <<= 4
     283:	r3 &= 16
     284:	r1 &= 65516
     285:	r3 |= r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	*(u16 *)(r7 + 36) = r3
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r2 &= 1
     288:	r8 = 60
     289:	if r2 == 0 goto +1 <LBB9_45>
     290:	r8 = 21600

LBB9_45:
     291:	call 5
     292:	r0 /= 1000000000
     293:	r8 += r0
     294:	*(u32 *)(r7 + 32) = r8
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	r2 = *(u8 *)(r7 + 43)
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r1 = r2
     297:	r3 = *(u64 *)(r10 - 176)
     298:	r1 |= r3
; if (svc && svc->count != 0)
     299:	r3 = r1
     300:	r3 &= 255
     301:	r9 = *(u64 *)(r10 - 168)
     302:	if r2 != r3 goto +10 <LBB9_47>
     303:	r2 = 0
     304:	*(u64 *)(r10 - 240) = r2
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	r2 = *(u32 *)(r7 + 52)
     306:	r2 += 5
; uint32_t hash = get_hash_recalc(skb);
     307:	r3 = r0
     308:	r3 <<= 32
; struct debug_msg msg = {
     309:	r3 >>= 32
     310:	r2 <<= 32
     311:	r2 >>= 32
     312:	if r2 >= r3 goto +300 <LBB9_52>

LBB9_47:
     313:	*(u8 *)(r7 + 43) = r1
     314:	*(u32 *)(r7 + 52) = r0
     315:	r1 = 128
     316:	*(u64 *)(r10 - 240) = r1
     317:	goto +295 <LBB9_52>

LBB9_8:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	r1 = 0
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	*(u8 *)(r10 - 99) = r1
     320:	*(u16 *)(r10 - 40) = r1
     321:	r7 = 4294967159 ll

LBB9_26:
     323:	r1 = r10
     324:	r1 += -40
     325:	goto +1173 <LBB9_191>

LBB9_7:
     326:	r1 = *(u16 *)(r8 + 20)
     327:	*(u64 *)(r10 - 200) = r1
     328:	r3 = 0
     329:	*(u8 *)(r10 - 99) = r3
     330:	r1 = 0
     331:	*(u64 *)(r10 - 208) = r1
     332:	*(u16 *)(r10 - 40) = r3
; __u8 flags = tuple->flags;
     333:	r3 = r10
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	r3 += -104
; union tcp_flags tcp_flags = { 0 };
     335:	r1 = r9
     336:	r4 = 4
; tuple->flags = TUPLE_F_SERVICE;
     337:	call 26
     338:	r1 = 1
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	*(u64 *)(r10 - 224) = r1
     340:	r2 = 6
     341:	r8 = 32
     342:	r1 = 0 ll
     344:	*(u64 *)(r10 - 176) = r1
; switch (tuple->nexthdr) {
     345:	r7 = 4294967161 ll
     347:	r1 = r10
     348:	r1 += -40
     349:	r0 <<= 32
     350:	r0 s>>= 32
; __u8 type;
     351:	if r0 s< 0 goto +1147 <LBB9_191>
     352:	goto -253 <LBB9_28>

LBB9_9:
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	r1 &= 255
     354:	r5 = 0 ll
     356:	*(u64 *)(r10 - 176) = r5
     357:	if r1 == 6 goto +3 <LBB9_11>
     358:	r5 = 0 ll
     360:	*(u64 *)(r10 - 176) = r5

LBB9_11:
     361:	r2 = *(u16 *)(r8 + 20)
; tuple->dport = 0;
     362:	*(u64 *)(r10 - 200) = r2
     363:	r2 = 0
; tuple->sport = 0;
     364:	*(u8 *)(r10 - 99) = r2
     365:	*(u16 *)(r10 - 40) = r2
     366:	r2 = 1
; switch (type) {
     367:	*(u64 *)(r10 - 208) = r2
     368:	if r1 == 6 goto +2 <LBB9_13>
     369:	r2 = 0
     370:	*(u64 *)(r10 - 208) = r2

LBB9_13:
     371:	r7 = 4294967159 ll
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r2 = r10
     374:	r2 += -40
     375:	if r1 != 1 goto +1123 <LBB9_191>
     376:	r3 = r10
     377:	r3 += -96
     378:	r1 = 1
     379:	*(u64 *)(r10 - 224) = r1
     380:	r1 = r9
     381:	r2 = *(u64 *)(r10 - 192)
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	r4 = 1
     383:	call 26
     384:	r0 <<= 32
     385:	r0 s>>= 32
     386:	if r0 s< 0 goto +350 <LBB9_25>
     387:	r1 = 0
     388:	*(u32 *)(r10 - 104) = r1
     389:	r1 = *(u8 *)(r10 - 96)
     390:	if r1 s> 10 goto +349 <LBB9_19>
     391:	if r1 == 0 goto +384 <LBB9_21>
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     392:	if r1 == 3 goto +349 <LBB9_20>
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	if r1 == 8 goto +1 <LBB9_23>
     394:	goto +385 <LBB9_24>

LBB9_23:
     395:	r1 = 8
     396:	*(u16 *)(r10 - 102) = r1
     397:	goto +382 <LBB9_24>

LBB9_53:
     398:	r2 = *(u8 *)(r10 - 99)
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	r1 = r2
     400:	r1 |= 1
     401:	r3 = r2
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r3 &= 1
     403:	if r3 == 0 goto +2 <LBB9_55>
     404:	r2 &= 254
     405:	r1 = r2

LBB9_55:
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	r2 = *(u32 *)(r10 - 108)
     407:	r3 = *(u32 *)(r10 - 112)
     408:	*(u32 *)(r10 - 108) = r3
     409:	*(u32 *)(r10 - 112) = r2
     410:	r2 = *(u16 *)(r10 - 102)
     411:	r3 = *(u16 *)(r10 - 104)
     412:	*(u16 *)(r10 - 102) = r3
     413:	*(u16 *)(r10 - 104) = r2
     414:	*(u8 *)(r10 - 99) = r1
     415:	r1 = *(u8 *)(r10 - 40)
     416:	*(u64 *)(r10 - 264) = r1
     417:	r6 = *(u8 *)(r10 - 39)
     418:	r2 = r10
     419:	r2 += -112
; tuple->flags |= TUPLE_F_RELATED;
     420:	r1 = r8
     421:	call 1
     422:	r7 = r0
     423:	if r7 != 0 goto +4 <LBB9_58>
; break;
     424:	r8 = 0

LBB9_57:
     425:	r1 = 128
; tuple->sport = type;
     426:	*(u64 *)(r10 - 240) = r1
     427:	goto +189 <LBB9_81>

LBB9_58:
     428:	*(u64 *)(r10 - 176) = r6
     429:	r6 = *(u16 *)(r7 + 38)
     430:	r8 = *(u32 *)(r7 + 32)
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	r1 = r9
     432:	call 34
     433:	*(u32 *)(r10 - 92) = r0
     434:	r1 = 269486082
     435:	*(u32 *)(r10 - 96) = r1
     436:	*(u32 *)(r10 - 88) = r8
     437:	*(u32 *)(r10 - 84) = r6
     438:	r1 = 0
     439:	*(u32 *)(r10 - 80) = r1
     440:	r4 = r10
     441:	r4 += -96
     442:	r1 = r9
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	r2 = 0 ll
     445:	r3 = 4294967295 ll
     447:	r5 = 20
     448:	call 25
     449:	r1 = *(u16 *)(r7 + 36)
     450:	r2 = r1
     451:	r2 &= 3
     452:	r4 = 128
     453:	r6 = *(u64 *)(r10 - 224)
     454:	if r2 == 3 goto +44 <LBB9_65>
     455:	r9 = 60
     456:	r2 = *(u64 *)(r10 - 208)
     457:	r2 &= 1
     458:	if r2 == 0 goto +16 <LBB9_62>
     459:	r2 = *(u64 *)(r10 - 264)
     460:	r2 ^= 1
     461:	r2 &= 255
     462:	r3 = r1
     463:	r3 >>= 4
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	r3 |= r2
     465:	r2 = r3
     466:	r2 <<= 4
     467:	r2 &= 16
     468:	r1 &= 65519
     469:	r2 |= r1
     470:	*(u16 *)(r7 + 36) = r2
; uint32_t hash = get_hash_recalc(skb);
     471:	r3 &= 1
     472:	r9 = 60
; struct debug_msg msg = {
     473:	if r3 == 0 goto +1 <LBB9_62>
     474:	r9 = 21600

LBB9_62:
     475:	call 5
     476:	r0 /= 1000000000
     477:	r9 += r0
     478:	*(u32 *)(r7 + 32) = r9
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	r2 = *(u8 *)(r7 + 43)
     480:	r1 = r2
     481:	r3 = *(u64 *)(r10 - 176)
     482:	r1 |= r3
     483:	r3 = r1
     484:	r3 &= 255
     485:	r9 = *(u64 *)(r10 - 168)
     486:	if r2 != r3 goto +9 <LBB9_64>
     487:	r4 = 0
; struct debug_msg msg = {
     488:	r2 = *(u32 *)(r7 + 52)
     489:	r2 += 5
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     490:	r3 = r0
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     491:	r3 <<= 32
     492:	r3 >>= 32
     493:	r2 <<= 32
     494:	r2 >>= 32
     495:	if r2 >= r3 goto +3 <LBB9_65>

LBB9_64:
     496:	*(u8 *)(r7 + 43) = r1
     497:	*(u32 *)(r7 + 52) = r0
     498:	r4 = 128

LBB9_65:
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     499:	*(u64 *)(r10 - 240) = r4
     500:	r1 = *(u16 *)(r7 + 38)
; uint32_t hash = get_hash_recalc(skb);
     501:	*(u16 *)(r10 - 136) = r1
     502:	r1 = *(u16 *)(r10 - 134)
; struct debug_msg msg = {
     503:	r1 &= 65534
     504:	r2 = *(u16 *)(r7 + 36)
     505:	r3 = r2
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
     506:	r3 >>= 3
     507:	r3 &= 1
; struct debug_msg msg = {
     508:	r1 |= r3
     509:	*(u16 *)(r10 - 134) = r1
     510:	r1 = *(u16 *)(r7 + 40)
     511:	*(u16 *)(r10 - 116) = r1
     512:	r2 &= 4
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     513:	if r2 == 0 goto +4 <LBB9_68>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     514:	r1 = *(u32 *)(r9 + 60)
     515:	if r1 != 0 goto +2 <LBB9_68>
     516:	r1 = 2
     517:	*(u32 *)(r9 + 60) = r1

LBB9_68:
     518:	r8 = 1
     519:	r1 = 1
     520:	lock *(u64 *)(r7 + 0) += r1
     521:	r1 = *(u32 *)(r9 + 0)
     522:	lock *(u64 *)(r7 + 8) += r1
; if ((entry = map_lookup_elem(map, tuple))) {
     523:	if r6 == 2 goto +222 <LBB9_77>
     524:	r6 <<= 32
     525:	r6 >>= 32
     526:	if r6 != 1 goto +90 <LBB9_81>
     527:	r1 = *(u16 *)(r7 + 36)
     528:	r2 = r1
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     529:	r2 &= 1
     530:	r3 = r1
     531:	r3 >>= 1
     532:	r3 &= 1
; uint32_t hash = get_hash_recalc(skb);
     533:	r3 = -r3
     534:	if r2 == r3 goto +82 <LBB9_81>
; struct debug_msg msg = {
     535:	r2 = r1
     536:	r2 &= 65532
     537:	*(u16 *)(r7 + 36) = r2
     538:	r8 = 60
     539:	r2 = *(u64 *)(r10 - 208)
     540:	r2 &= 1
     541:	if r2 == 0 goto +16 <LBB9_74>
     542:	r3 = *(u64 *)(r10 - 264)
     543:	r3 ^= 1
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
     544:	r3 &= 255
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     545:	r2 = r1
     546:	r2 >>= 4
     547:	r2 |= r3
     548:	r3 = r2
     549:	r3 <<= 4
     550:	r3 &= 16
     551:	r1 &= 65516
; return !entry->rx_closing || !entry->tx_closing;
     552:	r3 |= r1
     553:	*(u16 *)(r7 + 36) = r3
     554:	r2 &= 1
; if (ct_entry_alive(entry)) {
     555:	r8 = 60
     556:	if r2 == 0 goto +1 <LBB9_74>
; if (tcp) {
     557:	r8 = 21600

LBB9_74:
     558:	call 5
; entry->seen_non_syn |= !syn;
     559:	r0 /= 1000000000
     560:	r8 += r0
     561:	*(u32 *)(r7 + 32) = r8
     562:	r2 = *(u8 *)(r7 + 43)
     563:	r1 = r2
     564:	r3 = *(u64 *)(r10 - 176)
     565:	r1 |= r3
     566:	r3 = r1
     567:	r3 &= 255
     568:	r9 = *(u64 *)(r10 - 168)
     569:	r8 = 1
     570:	if r2 != r3 goto +10 <LBB9_76>
; if (entry->seen_non_syn)
     571:	r2 = 0
     572:	*(u64 *)(r10 - 240) = r2
     573:	r2 = *(u32 *)(r7 + 52)
     574:	r2 += 5
; return ktime_get_ns();
     575:	r3 = r0
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     576:	r3 <<= 32
; entry->lifetime = now + lifetime;
     577:	r3 >>= 32
     578:	r2 <<= 32
; seen_flags |= *accumulated_flags;
     579:	r2 >>= 32
     580:	if r2 >= r3 goto +36 <LBB9_81>

LBB9_76:
     581:	*(u8 *)(r7 + 43) = r1
     582:	*(u32 *)(r7 + 52) = r0
     583:	goto -159 <LBB9_57>

LBB9_48:
     584:	r1 = *(u16 *)(r7 + 36)
; if (*last_report + CT_REPORT_INTERVAL < now ||
     585:	r1 |= 1
     586:	*(u16 *)(r7 + 36) = r1
     587:	r2 = 128
     588:	*(u64 *)(r10 - 240) = r2
     589:	r1 &= 3
     590:	if r1 != 3 goto +22 <LBB9_52>
     591:	call 5
     592:	r0 /= 1000000000
     593:	r1 = r0
; *accumulated_flags = seen_flags;
     594:	r1 += 10
; *last_report = now;
     595:	*(u32 *)(r7 + 32) = r1
; ct_state->slave = entry->slave;
     596:	r2 = *(u8 *)(r7 + 43)
; ct_state->rev_nat_index = entry->rev_nat_index;
     597:	r1 = r2
     598:	r3 = *(u64 *)(r10 - 176)
; ct_state->loopback = entry->lb_loopback;
     599:	r1 |= r3
     600:	r3 = r1
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
     601:	r3 &= 255
     602:	if r2 != r3 goto +8 <LBB9_51>
     603:	r2 = *(u32 *)(r7 + 52)
     604:	r2 += 5
     605:	r3 = r0
; skb->cb[CB_NAT46_STATE] = NAT46;
     606:	r3 <<= 32
     607:	r3 >>= 32
     608:	r2 <<= 32
; __sync_fetch_and_add(&entry->tx_packets, 1);
     609:	r2 >>= 32
     610:	if r2 >= r3 goto +2 <LBB9_52>

LBB9_51:
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
     611:	*(u8 *)(r7 + 43) = r1
     612:	*(u32 *)(r7 + 52) = r0

LBB9_52:
     613:	r8 = *(u8 *)(r10 - 99)
     614:	r8 >>= 1
; switch (action) {
     615:	r8 &= 1
     616:	r8 |= 2

LBB9_81:
     617:	r6 = *(u16 *)(r10 - 136)
     618:	r1 = r9
; ret = entry->rx_closing + entry->tx_closing;
     619:	call 34
     620:	*(u32 *)(r10 - 92) = r0
     621:	r1 = 269487874
     622:	*(u32 *)(r10 - 96) = r1
     623:	*(u64 *)(r10 - 176) = r8
     624:	*(u32 *)(r10 - 88) = r8
; if (unlikely(ret >= 1)) {
     625:	*(u32 *)(r10 - 84) = r6
     626:	r1 = 0
     627:	*(u32 *)(r10 - 80) = r1
     628:	r4 = r10
; entry->tx_closing = 0;
     629:	r4 += -96
     630:	r1 = r9
     631:	r2 = 0 ll
; if (tcp) {
     633:	r3 = 4294967295 ll
     635:	r5 = 20
; entry->seen_non_syn |= !syn;
     636:	call 25
     637:	r2 = 1500
     638:	r8 = *(u16 *)(r10 - 104)
     639:	if r8 == 13568 goto +1 <LBB9_83>
     640:	r2 = *(u64 *)(r10 - 240)

LBB9_83:
     641:	r1 = *(u32 *)(r9 + 60)
     642:	r6 = *(u64 *)(r10 - 184)
     643:	if r1 == 2 goto +1 <LBB9_84>
     644:	goto +8 <LBB9_85>

LBB9_84:
     645:	r1 = r9
     646:	r2 = 0 ll
; if (entry->seen_non_syn)
     648:	r3 = 9
     649:	call 12
     650:	r7 = 4294967156 ll
; return ktime_get_ns();
     652:	goto +846 <LBB9_191>

LBB9_85:
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     653:	*(u64 *)(r10 - 208) = r2
; entry->lifetime = now + lifetime;
     654:	r1 = *(u64 *)(r10 - 176)
     655:	if r1 != 2 goto +348 <LBB9_129>
     656:	r7 = *(u16 *)(r10 - 136)
; seen_flags |= *accumulated_flags;
     657:	if r7 == 0 goto +346 <LBB9_129>
     658:	r1 = *(u8 *)(r10 - 134)
     659:	r1 &= 1
     660:	if r1 != 0 goto +343 <LBB9_129>
     661:	r6 = *(u64 *)(r10 - 168)
     662:	r1 = r6
     663:	call 34
; if (*last_report + CT_REPORT_INTERVAL < now ||
     664:	*(u32 *)(r10 - 92) = r0
     665:	r1 = 269492226
     666:	*(u32 *)(r10 - 96) = r1
     667:	*(u32 *)(r10 - 88) = r7
     668:	r1 = 0
     669:	*(u32 *)(r10 - 84) = r1
     670:	*(u32 *)(r10 - 80) = r1
     671:	r4 = r10
     672:	r4 += -96
; *accumulated_flags = seen_flags;
     673:	r1 = r6
; *last_report = now;
     674:	r2 = 0 ll
     676:	r3 = 4294967295 ll
     678:	r5 = 20
     679:	call 25
; switch(ret) {
     680:	r2 = r10
     681:	r2 += -136
; tuple->flags = flags;
     682:	r1 = 0 ll
     684:	call 1
     685:	r7 = 0
; if (IS_ERR(ret))
     686:	*(u64 *)(r10 - 224) = r0
     687:	if r0 == 0 goto +304 <LBB9_125>
     688:	r9 = *(u64 *)(r10 - 224)
     689:	r6 = *(u8 *)(r9 + 5)
     690:	r6 <<= 8
     691:	r1 = *(u8 *)(r9 + 4)
     692:	r6 |= r1
     693:	r1 = *(u8 *)(r9 + 2)
     694:	*(u64 *)(r10 - 240) = r1
     695:	r7 = *(u8 *)(r9 + 3)
; dst->p4 = src->p4;
     696:	r1 = *(u8 *)(r9 + 0)
; dst->p3 = src->p3;
     697:	*(u64 *)(r10 - 264) = r1
     698:	r8 = *(u8 *)(r9 + 1)
; dst->p2 = src->p2;
     699:	r1 = *(u64 *)(r10 - 168)
; dst->p1 = src->p1;
     700:	call 34
     701:	*(u32 *)(r10 - 92) = r0
; if (tuple->nexthdr == IPPROTO_TCP) {
     702:	r1 = 269492482
     703:	*(u32 *)(r10 - 96) = r1
; union tcp_flags tcp_flags = { 0 };
     704:	*(u32 *)(r10 - 84) = r6
     705:	r6 = 0
; tuple->flags = TUPLE_F_IN;
     706:	*(u32 *)(r10 - 80) = r6
     707:	r8 <<= 8
; ret = ct_lookup6(get_ct_map6(tuple), tuple, skb, l4_off, CT_EGRESS,
     708:	r1 = *(u64 *)(r10 - 264)
     709:	r8 |= r1
     710:	r7 <<= 8
     711:	r1 = *(u64 *)(r10 - 240)
     712:	r7 |= r1
     713:	r7 <<= 16
     714:	r7 |= r8
; switch (tuple->nexthdr) {
     715:	*(u32 *)(r10 - 88) = r7
     716:	r4 = r10
     717:	r4 += -96
     718:	r1 = *(u64 *)(r10 - 168)
     719:	r2 = 0 ll
     721:	r3 = 4294967295 ll
     723:	r5 = 20
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     724:	call 25
     725:	r1 = *(u8 *)(r9 + 4)
     726:	r8 = *(u8 *)(r9 + 5)
     727:	r8 <<= 8
     728:	r8 |= r1
     729:	if r8 == 0 goto +122 <LBB9_109>
     730:	r7 = 4294967154 ll
     732:	r1 = *(u8 *)(r10 - 100)
; tuple->dport = 0;
     733:	if r1 s> 16 goto +51 <LBB9_93>
     734:	if r1 == 1 goto +107 <LBB9_105>
; tuple->sport = 0;
     735:	if r1 == 6 goto +51 <LBB9_95>
     736:	goto +106 <LBB9_106>

LBB9_25:
; tuple->dport = 0;
     737:	r7 = 4294967161 ll
     739:	goto -417 <LBB9_26>

LBB9_19:
; switch (type) {
     740:	r1 += -11
     741:	if r1 > 1 goto +38 <LBB9_24>

LBB9_20:
     742:	r1 = *(u8 *)(r10 - 99)
     743:	r1 |= 2
     744:	*(u8 *)(r10 - 99) = r1
     745:	goto +32 <LBB9_22>

LBB9_77:
; tuple->dport = ICMPV6_ECHO_REQUEST;
     746:	r1 = *(u16 *)(r7 + 36)
     747:	r1 |= 1
     748:	*(u16 *)(r7 + 36) = r1
     749:	r2 = 128
     750:	*(u64 *)(r10 - 240) = r2
     751:	r1 &= 3
     752:	if r1 != 3 goto -136 <LBB9_81>
     753:	call 5
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     754:	r0 /= 1000000000
     755:	r1 = r0
     756:	r1 += 10
     757:	*(u32 *)(r7 + 32) = r1
     758:	r2 = *(u8 *)(r7 + 43)
     759:	r1 = r2
     760:	r3 = *(u64 *)(r10 - 176)
     761:	r1 |= r3
     762:	r3 = r1
     763:	r3 &= 255
     764:	if r2 != r3 goto +8 <LBB9_80>
     765:	r2 = *(u32 *)(r7 + 52)
     766:	r2 += 5
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     767:	r3 = r0
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     768:	r3 <<= 32
     769:	r3 >>= 32
     770:	r2 <<= 32
     771:	r2 >>= 32
     772:	if r2 >= r3 goto -156 <LBB9_81>

LBB9_80:
     773:	*(u8 *)(r7 + 43) = r1
     774:	*(u32 *)(r7 + 52) = r0
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     775:	goto -159 <LBB9_81>

LBB9_21:
     776:	r1 = 8
     777:	*(u16 *)(r10 - 104) = r1

LBB9_22:
     778:	r1 = 0
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     779:	*(u64 *)(r10 - 224) = r1

LBB9_24:
     780:	r8 = 0
     781:	r1 = r10
     782:	r1 += -40
     783:	r2 = 0
     784:	goto -685 <LBB9_28>

LBB9_93:
     785:	if r1 == 58 goto +56 <LBB9_105>
; tuple->flags |= TUPLE_F_RELATED;
     786:	if r1 != 17 goto +56 <LBB9_106>

LBB9_95:
     787:	r3 = r10
     788:	r3 += -40
     789:	r1 = *(u64 *)(r10 - 168)
; break;
     790:	r2 = *(u64 *)(r10 - 192)
     791:	r4 = 2
     792:	call 26
     793:	r7 = r0
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
     794:	r1 = r7
     795:	r1 <<= 32
     796:	r1 >>= 32
     797:	r2 = 1
     798:	if r1 == 2 goto +1 <LBB9_97>
     799:	r2 = 0

LBB9_97:
     800:	r1 >>= 31
     801:	r1 |= r2
     802:	if r1 != 0 goto +38 <LBB9_104>
; if (dir == CT_INGRESS)
     803:	r3 = *(u16 *)(r10 - 40)
     804:	if r3 == r8 goto +37 <LBB9_105>
; return !entry->rx_closing || !entry->tx_closing;
     805:	r2 = *(u64 *)(r10 - 248)
; if (ct_entry_alive(entry))
     806:	r2 &= 65535
; return ktime_get_ns();
     807:	r1 = *(u64 *)(r10 - 192)
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     808:	r2 += r1
; entry->lifetime = now + lifetime;
     809:	*(u16 *)(r10 - 96) = r8
     810:	r5 = *(u64 *)(r10 - 256)
     811:	r5 |= 2
; seen_flags |= *accumulated_flags;
     812:	r5 &= 65535
     813:	r1 = *(u64 *)(r10 - 168)
     814:	r4 = r8
     815:	call 11
     816:	r7 = 4294967142 ll
; if (*last_report + CT_REPORT_INTERVAL < now ||
     818:	r0 <<= 32
     819:	r0 s>>= 32
     820:	if r0 s< 0 goto +11 <LBB9_101>
     821:	r3 = r10
     822:	r3 += -96
     823:	r1 = *(u64 *)(r10 - 168)
     824:	r2 = *(u64 *)(r10 - 192)
     825:	r4 = 2
     826:	r5 = 0
; *accumulated_flags = seen_flags;
     827:	call 9
; *last_report = now;
     828:	r7 = r0
     829:	r7 <<= 32
     830:	r7 s>>= 63
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
     831:	r7 &= -141

LBB9_101:
     832:	r1 = r7
     833:	r1 <<= 32
     834:	r1 >>= 32
     835:	r2 = 1
; uint32_t hash = get_hash_recalc(skb);
     836:	if r1 == 2 goto +1 <LBB9_103>
     837:	r2 = 0

LBB9_103:
; struct debug_msg msg = {
     838:	r1 >>= 31
     839:	r1 |= r2
     840:	if r1 == 0 goto +1 <LBB9_105>

LBB9_104:
     841:	goto +1 <LBB9_106>

LBB9_105:
     842:	r7 = 0

LBB9_106:
     843:	r1 = r7
     844:	r1 <<= 32
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
     845:	r1 >>= 32
; struct debug_msg msg = {
     846:	r2 = 1
     847:	if r1 == 2 goto +1 <LBB9_108>
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
     848:	r2 = 0

LBB9_108:
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     849:	r1 >>= 31
     850:	r1 |= r2
     851:	if r1 != 0 goto +140 <LBB9_125>

LBB9_109:
     852:	r1 = *(u32 *)(r10 - 108)
     853:	*(u32 *)(r10 - 40) = r1
     854:	r3 = *(u64 *)(r10 - 224)
     855:	r1 = *(u8 *)(r3 + 1)
     856:	r1 <<= 8
; switch(ret) {
     857:	r2 = *(u8 *)(r3 + 0)
     858:	r1 |= r2
     859:	r2 = *(u8 *)(r3 + 2)
     860:	r3 = *(u8 *)(r3 + 3)
     861:	r3 <<= 8
     862:	r3 |= r2
     863:	r3 <<= 16
     864:	r3 |= r1
     865:	*(u32 *)(r10 - 108) = r3
     866:	*(u32 *)(r10 - 16) = r3
     867:	r1 = *(u8 *)(r10 - 134)
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     868:	r1 &= 1
     869:	if r1 == 0 goto +66 <LBB9_118>
     870:	r3 = r10
     871:	r3 += -144
     872:	r1 = *(u64 *)(r10 - 168)
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     873:	r2 = 30
     874:	r4 = 4
; struct lb6_service *svc;
     875:	call 26
; skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
     876:	r7 = r0
     877:	r1 = r7
     878:	r1 <<= 32
     879:	r1 >>= 32
     880:	r2 = 1
; skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
     881:	if r1 == 2 goto +1 <LBB9_112>
     882:	r2 = 0

LBB9_112:
     883:	r1 >>= 31
     884:	r1 |= r2
     885:	if r1 != 0 goto +38 <LBB9_116>
     886:	r6 = *(u32 *)(r10 - 40)
; state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
     887:	r7 = *(u32 *)(r10 - 144)
     888:	r8 = *(u64 *)(r10 - 168)
; return get_hash_recalc(skb);
     889:	r1 = r8
     890:	call 34
     891:	*(u32 *)(r10 - 92) = r0
; if (weight) {
     892:	r1 = 269492994
     893:	*(u32 *)(r10 - 96) = r1
; struct lb6_key *key,
     894:	*(u32 *)(r10 - 88) = r7
; seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
     895:	*(u32 *)(r10 - 84) = r6
     896:	r1 = 0
     897:	*(u32 *)(r10 - 80) = r1
; if (seq && seq->count != 0)
     898:	r4 = r10
     899:	r4 += -96
     900:	r1 = r8
; slave = lb_next_rr(skb, seq, hash);
     901:	r2 = 0 ll
; __u8 offset = hash % seq->count;
     903:	r3 = 4294967295 ll
     905:	r5 = 20
     906:	call 25
     907:	r3 = r10
; if (offset < LB_RR_MAX_SEQ) {
     908:	r3 += -40
     909:	r1 = r8
; slave = seq->idx[offset] + 1;
     910:	r2 = 30
     911:	r4 = 4
     912:	r5 = 0
; uint32_t hash = get_hash_recalc(skb);
     913:	call 9
     914:	r0 <<= 32
; struct debug_msg msg = {
     915:	r0 >>= 32
     916:	r1 = 1
     917:	if r0 == 2 goto +1 <LBB9_115>
     918:	r1 = 0

LBB9_115:
     919:	r0 >>= 31
     920:	r0 |= r1
     921:	r7 = 4294967155 ll
     923:	if r0 == 0 goto +1 <LBB9_117>

LBB9_116:
     924:	goto +67 <LBB9_125>

LBB9_117:
     925:	r1 = r10
; uint32_t hash = get_hash_recalc(skb);
     926:	r1 += -144
     927:	r3 = r10
; struct debug_msg msg = {
     928:	r3 += -40
     929:	r2 = 4
     930:	r4 = 4
     931:	r5 = 0
     932:	call 28
     933:	r6 = r0
; slave = (hash % count) + 1;
     934:	r1 = *(u32 *)(r10 - 40)
     935:	*(u32 *)(r10 - 108) = r1

LBB9_118:
     936:	r3 = r10
     937:	r3 += -16
     938:	r1 = *(u64 *)(r10 - 168)
     939:	r2 = 26
     940:	r4 = 4
; struct debug_msg msg = {
     941:	r5 = 0
     942:	call 9
     943:	r0 <<= 32
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     944:	r0 >>= 32
     945:	r1 = 1
     946:	if r0 == 2 goto +1 <LBB9_120>
     947:	r1 = 0

LBB9_120:
     948:	r0 >>= 31
     949:	r0 |= r1
     950:	r7 = 4294967155 ll
     952:	if r0 != 0 goto +39 <LBB9_125>
     953:	r1 = r10
; struct ct_entry entry = { };
     954:	r1 += -40
     955:	r3 = r10
     956:	r3 += -16
     957:	r2 = 4
     958:	r4 = 4
     959:	r5 = r6
     960:	call 28
; bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
     961:	r6 = r0
     962:	r1 = *(u64 *)(r10 - 168)
; entry.rev_nat_index = ct_state->rev_nat_index;
     963:	r2 = 24
     964:	r3 = 0
; entry.slave = ct_state->slave;
     965:	r4 = r6
; entry.lb_loopback = ct_state->loopback;
     966:	r5 = 0
     967:	call 10
     968:	r7 = 4294967143 ll
; entry->seen_non_syn |= !syn;
     970:	r0 <<= 32
     971:	r0 s>>= 32
; return ktime_get_ns();
     972:	if r0 s< 0 goto +19 <LBB9_125>
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     973:	r1 = *(u64 *)(r10 - 248)
; entry->lifetime = now + lifetime;
     974:	if r1 == 0 goto +16 <LBB9_124>
     975:	r2 = *(u64 *)(r10 - 248)
     976:	r2 &= 65535
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
     977:	r1 = *(u64 *)(r10 - 192)
     978:	r2 += r1
     979:	r5 = *(u64 *)(r10 - 256)
; if (*last_report + CT_REPORT_INTERVAL < now ||
     980:	r5 |= 16
     981:	r5 &= 65535
     982:	r1 = *(u64 *)(r10 - 168)
     983:	r3 = 0
     984:	r4 = r6
; *last_report = now;
     985:	call 11
     986:	r7 = 4294967142 ll
; entry.tx_bytes = skb->len;
     988:	r0 <<= 32
     989:	r0 s>>= 32
; uint32_t hash = get_hash_recalc(skb);
     990:	if r0 s< 0 goto +1 <LBB9_125>

LBB9_124:
     991:	r7 = 0

LBB9_125:
; struct debug_msg msg = {
     992:	r1 = r7
     993:	r1 <<= 32
     994:	r1 >>= 32
     995:	r2 = 1
     996:	if r1 == 2 goto +1 <LBB9_127>
     997:	r2 = 0

LBB9_127:
     998:	r1 >>= 31
     999:	r1 |= r2
; entry.tx_packets = 1;
    1000:	r9 = *(u64 *)(r10 - 168)
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1001:	r6 = *(u64 *)(r10 - 184)
    1002:	if r1 != 0 goto +496 <LBB9_191>
    1003:	r8 = *(u16 *)(r10 - 104)

LBB9_129:
    1004:	r1 = *(u64 *)(r10 - 200)
    1005:	r1 &= 65471
    1006:	r9 = *(u8 *)(r10 - 100)
    1007:	*(u16 *)(r10 - 36) = r8
; entry.src_sec_id = ct_state->src_sec_id;
    1008:	*(u32 *)(r10 - 40) = r6
    1009:	r7 = 0
; entry.tx_packets = 1;
    1010:	*(u8 *)(r10 - 33) = r7
    1011:	*(u8 *)(r10 - 34) = r9
; if (map_update_elem(map, tuple, &entry, 0) < 0)
    1012:	*(u64 *)(r10 - 200) = r1
    1013:	if r1 != 0 goto +38 <LBB9_132>
    1014:	r2 = r10
    1015:	r2 += -40
    1016:	r1 = 0 ll
    1018:	call 1
    1019:	*(u64 *)(r10 - 224) = r0
    1020:	if r0 == 0 goto +31 <LBB9_132>
; tuple->sport = type;
    1021:	r7 = r6
    1022:	r6 = *(u64 *)(r10 - 168)
    1023:	r1 = r6
    1024:	call 34
    1025:	*(u32 *)(r10 - 92) = r0
    1026:	r1 = 269497090
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
    1027:	*(u32 *)(r10 - 96) = r1
    1028:	*(u32 *)(r10 - 88) = r7
    1029:	r1 = 2
    1030:	*(u32 *)(r10 - 84) = r1
    1031:	r8 <<= 16
    1032:	r8 |= r9
    1033:	r9 = r6
    1034:	*(u32 *)(r10 - 80) = r8
    1035:	r4 = r10
    1036:	r4 += -96
    1037:	r1 = r9
    1038:	r2 = 0 ll
    1040:	r3 = 4294967295 ll
    1042:	r5 = 20
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1043:	call 25
    1044:	r1 = 1
    1045:	r2 = *(u64 *)(r10 - 224)
    1046:	lock *(u64 *)(r2 + 8) += r1

LBB9_137:
    1047:	r1 = *(u32 *)(r9 + 0)
    1048:	lock *(u64 *)(r2 + 16) += r1
    1049:	r3 = *(u16 *)(r2 + 0)
    1050:	r6 = *(u64 *)(r10 - 184)
    1051:	goto +14 <LBB9_138>

LBB9_132:
    1052:	*(u8 *)(r10 - 34) = r7
    1053:	*(u16 *)(r10 - 36) = r7
    1054:	r2 = r10
    1055:	r2 += -40
    1056:	r1 = 0 ll
    1058:	call 1
    1059:	if r0 == 0 goto +498 <LBB9_134>
    1060:	r1 = 1
    1061:	lock *(u64 *)(r0 + 8) += r1
    1062:	r9 = *(u64 *)(r10 - 168)
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1063:	r1 = *(u32 *)(r9 + 0)
    1064:	lock *(u64 *)(r0 + 16) += r1
    1065:	r3 = 0

LBB9_138:
    1066:	r7 = *(u64 *)(r10 - 216)
    1067:	r8 = *(u64 *)(r10 - 176)

LBB9_139:
    1068:	r7 &= 1
    1069:	if r7 == 0 goto +1 <LBB9_147>
    1070:	r3 = 0

LBB9_147:
    1071:	if r8 != 0 goto +94 <LBB9_159>
    1072:	r1 = *(u8 *)(r10 - 100)
    1073:	r2 = 0
    1074:	*(u64 *)(r10 - 48) = r2
; uint32_t hash = get_hash_recalc(skb);
    1075:	*(u64 *)(r10 - 56) = r2
    1076:	*(u64 *)(r10 - 64) = r2
; struct debug_msg msg = {
    1077:	*(u64 *)(r10 - 72) = r2
    1078:	*(u64 *)(r10 - 80) = r2
    1079:	*(u64 *)(r10 - 88) = r2
    1080:	*(u64 *)(r10 - 96) = r2
    1081:	r7 = 0 ll
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
    1083:	if r1 == 6 goto +2 <LBB9_150>
    1084:	r7 = 0 ll

LBB9_150:
    1086:	*(u64 *)(r10 - 200) = r3
    1087:	if r1 != 6 goto +2 <LBB9_152>
    1088:	r1 = 0
    1089:	*(u16 *)(r10 - 60) = r1

LBB9_152:
    1090:	call 5
    1091:	r0 /= 1000000000
; struct debug_msg msg = {
    1092:	r1 = r0
    1093:	r1 += 60
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1094:	*(u32 *)(r10 - 64) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1095:	r1 = r0
    1096:	r1 <<= 32
    1097:	r1 >>= 32
    1098:	if r1 < 6 goto +1 <LBB9_154>
    1099:	*(u32 *)(r10 - 44) = r0

LBB9_154:
    1100:	r1 = 1
    1101:	*(u64 *)(r10 - 96) = r1
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1102:	r1 = *(u32 *)(r9 + 0)
    1103:	*(u64 *)(r10 - 88) = r1
    1104:	r1 = *(u32 *)(r9 + 60)
    1105:	if r1 != 1 goto +2 <LBB9_156>
; uint32_t hash = get_hash_recalc(skb);
    1106:	r1 = 0
    1107:	*(u16 *)(r10 - 60) = r1

LBB9_156:
; struct debug_msg msg = {
    1108:	r1 = r9
    1109:	call 34
    1110:	*(u32 *)(r10 - 36) = r0
; cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
    1111:	r1 = 269495810
    1112:	*(u32 *)(r10 - 40) = r1
    1113:	r8 = 0
; struct debug_msg msg = {
    1114:	*(u32 *)(r10 - 32) = r8
    1115:	*(u32 *)(r10 - 28) = r6
    1116:	*(u32 *)(r10 - 24) = r8
    1117:	r4 = r10
    1118:	r4 += -40
    1119:	r1 = r9
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
    1120:	r2 = 0 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1122:	r3 = 4294967295 ll
    1124:	r5 = 20
    1125:	call 25
    1126:	*(u32 *)(r10 - 52) = r6
    1127:	r2 = r10
    1128:	r2 += -112
    1129:	r3 = r10
    1130:	r3 += -96
; if ((entry = map_lookup_elem(map, tuple))) {
    1131:	r1 = r7
    1132:	r4 = 0
    1133:	call 2
    1134:	r0 <<= 32
    1135:	r0 s>>= 32
    1136:	if r0 s> -1 goto +3 <LBB9_158>
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1137:	r7 = 4294967141 ll
    1139:	goto +359 <LBB9_191>

LBB9_158:
; uint32_t hash = get_hash_recalc(skb);
    1140:	r1 = *(u8 *)(r10 - 99)
    1141:	r2 = *(u64 *)(r10 - 112)
; struct debug_msg msg = {
    1142:	*(u64 *)(r10 - 40) = r2
    1143:	r2 = 1
    1144:	*(u8 *)(r10 - 28) = r2
    1145:	r1 |= 2
    1146:	*(u8 *)(r10 - 27) = r1
    1147:	r1 = *(u16 *)(r10 - 60)
    1148:	r1 |= 16
    1149:	*(u16 *)(r10 - 60) = r1
    1150:	*(u32 *)(r10 - 32) = r8
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1151:	r2 = r10
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1152:	r2 += -40
    1153:	r3 = r10
    1154:	r3 += -96
    1155:	r1 = r7
    1156:	r4 = 0
    1157:	call 2
    1158:	r0 <<= 32
; return !entry->rx_closing || !entry->tx_closing;
    1159:	r7 = r0
    1160:	r7 s>>= 63
    1161:	r7 &= -155
    1162:	r0 s>>= 32
; if (ct_entry_alive(entry)) {
    1163:	r8 = *(u64 *)(r10 - 176)
    1164:	r3 = *(u64 *)(r10 - 200)
; if (tcp) {
    1165:	if r0 s< 0 goto +333 <LBB9_191>

LBB9_159:
    1166:	r1 = r8
; entry->seen_non_syn |= !syn;
    1167:	r1 <<= 32
    1168:	r1 >>= 32
    1169:	if r1 > 1 goto +90 <LBB9_182>
    1170:	r3 <<= 32
    1171:	r3 s>>= 32
    1172:	if r3 s< 1 goto +87 <LBB9_182>
    1173:	r1 = 95142176846542 ll
    1175:	*(u64 *)(r10 - 144) = r1
    1176:	r1 = 244920237338078 ll
    1178:	*(u64 *)(r10 - 152) = r1
; if (entry->seen_non_syn)
    1179:	r7 = *(u16 *)(r10 - 104)
    1180:	r1 = 4294964490 ll
    1182:	*(u32 *)(r10 - 4) = r1
; return ktime_get_ns();
    1183:	*(u64 *)(r10 - 200) = r3
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1184:	*(u16 *)(r10 - 12) = r3
; entry->lifetime = now + lifetime;
    1185:	r1 = *(u32 *)(r10 - 112)
    1186:	*(u32 *)(r10 - 16) = r1
; seen_flags |= *accumulated_flags;
    1187:	r1 = *(u16 *)(r10 - 102)
    1188:	*(u16 *)(r10 - 10) = r1
    1189:	r1 = *(u8 *)(r10 - 100)
    1190:	*(u8 *)(r10 - 8) = r1
    1191:	r8 = 0
    1192:	*(u8 *)(r10 - 7) = r8
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1193:	r1 = *(u64 *)(r10 - 232)
    1194:	*(u32 *)(r10 - 40) = r1
    1195:	*(u16 *)(r10 - 34) = r8
    1196:	*(u32 *)(r10 - 32) = r6
    1197:	*(u16 *)(r10 - 36) = r7
    1198:	call 5
    1199:	r0 /= 1000000000
    1200:	r0 += 720
    1201:	*(u32 *)(r10 - 28) = r0
; *accumulated_flags = seen_flags;
    1202:	r2 = *(u64 *)(r10 - 208)
; *last_report = now;
    1203:	r2 <<= 32
    1204:	r2 >>= 32
; ct_state->rev_nat_index = entry->rev_nat_index;
    1205:	if r2 == 0 goto +32 <LBB9_165>
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1206:	r1 = r9
    1207:	r9 = *(u32 *)(r1 + 0)
    1208:	r6 = r2
    1209:	call 34
    1210:	r3 = r6
    1211:	*(u32 *)(r10 - 92) = r0
    1212:	r1 = 269484292
; skb->cb[CB_NAT46_STATE] = NAT46;
    1213:	*(u32 *)(r10 - 96) = r1
    1214:	r1 = 2
    1215:	*(u64 *)(r10 - 80) = r1
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1216:	r1 = *(u64 *)(r10 - 176)
    1217:	*(u8 *)(r10 - 70) = r1
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1218:	*(u16 *)(r10 - 72) = r8
    1219:	*(u8 *)(r10 - 69) = r8
    1220:	r1 = 1
    1221:	*(u32 *)(r10 - 68) = r1
    1222:	*(u32 *)(r10 - 88) = r9
; switch (action) {
    1223:	if r3 < r9 goto +1 <LBB9_164>
    1224:	r3 = r9

LBB9_164:
    1225:	*(u32 *)(r10 - 84) = r3
    1226:	r3 <<= 32
; ret = entry->rx_closing + entry->tx_closing;
    1227:	r1 = 4294967295 ll
    1229:	r3 |= r1
    1230:	r4 = r10
    1231:	r4 += -96
    1232:	r9 = *(u64 *)(r10 - 168)
; if (unlikely(ret >= 1)) {
    1233:	r1 = r9
    1234:	r2 = 0 ll
; entry->tx_closing = 0;
    1236:	r5 = 32
    1237:	call 25

LBB9_165:
    1238:	r6 = r9
; if (tcp) {
    1239:	r9 = *(u64 *)(r10 - 248)
    1240:	r9 &= 65535
    1241:	r8 = *(u64 *)(r10 - 192)
; entry->seen_non_syn |= !syn;
    1242:	r9 += r8
    1243:	r4 = *(u64 *)(r10 - 200)
    1244:	*(u16 *)(r10 - 96) = r4
    1245:	r4 &= 65535
    1246:	r5 = *(u64 *)(r10 - 256)
    1247:	r5 |= 2
    1248:	r5 &= 65535
    1249:	r1 = r6
    1250:	r2 = r9
    1251:	r3 = r7
    1252:	*(u64 *)(r10 - 200) = r4
; if (entry->seen_non_syn)
    1253:	call 11
    1254:	r0 <<= 32
    1255:	r0 s>>= 32
    1256:	if r0 s> -1 goto +22 <LBB9_167>
; return ktime_get_ns();
    1257:	r7 = 4294967155 ll
; entry->lifetime = now + lifetime;
    1259:	goto +127 <LBB9_175>

LBB9_182:
    1260:	r7 = *(u32 *)(r9 + 0)
; seen_flags |= *accumulated_flags;
    1261:	r1 = 0
    1262:	*(u64 *)(r10 - 88) = r1
    1263:	*(u64 *)(r10 - 96) = r1
    1264:	r1 = 256
    1265:	*(u64 *)(r10 - 40) = r1
    1266:	r2 = r10
    1267:	r2 += -40
    1268:	r1 = 0 ll
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1270:	call 1
    1271:	if r0 == 0 goto +172 <LBB9_184>
    1272:	r1 = *(u64 *)(r0 + 0)
    1273:	r1 += 1
    1274:	*(u64 *)(r0 + 0) = r1
    1275:	r1 = *(u64 *)(r0 + 8)
    1276:	r1 += r7
    1277:	*(u64 *)(r0 + 8) = r1
    1278:	goto +176 <LBB9_185>

LBB9_167:
    1279:	r8 += 2
; *accumulated_flags = seen_flags;
    1280:	r3 = r10
; *last_report = now;
    1281:	r3 += -96
    1282:	r1 = r6
    1283:	r2 = r8
; tmp = tuple->sport;
    1284:	r4 = 2
; tuple->sport = tuple->dport;
    1285:	r5 = 0
    1286:	call 9
; tmp = tuple->sport;
    1287:	r7 = 4294967155 ll
; tuple->sport = tuple->dport;
    1289:	r0 <<= 32
; dst->p1 = src->p1;
    1290:	r0 s>>= 32
    1291:	if r0 s< 0 goto +95 <LBB9_175>
    1292:	r3 = r10
; dst->p2 = src->p2;
    1293:	r3 += -4
    1294:	r1 = *(u64 *)(r10 - 168)
    1295:	r2 = 30
    1296:	r4 = 4
; dst->p3 = src->p3;
    1297:	r5 = 0
    1298:	call 9
    1299:	r0 <<= 32
    1300:	r0 s>>= 32
; dst->p4 = src->p4;
    1301:	if r0 s< 0 goto +85 <LBB9_175>
    1302:	r4 = *(u32 *)(r10 - 4)
    1303:	r1 = *(u64 *)(r10 - 168)
    1304:	r2 = 24
; dst->p1 = src->p1;
    1305:	r3 = *(u64 *)(r10 - 232)
; tuple->dport = tmp;
    1306:	r5 = 4
    1307:	call 10
; if (tuple->flags & TUPLE_F_IN)
    1308:	r7 = 4294967143 ll
; tuple->flags |= TUPLE_F_IN;
    1310:	r0 <<= 32
; if (tuple->flags & TUPLE_F_IN)
    1311:	r0 s>>= 32
    1312:	if r0 s< 0 goto +74 <LBB9_175>
    1313:	r1 = *(u64 *)(r10 - 248)
    1314:	if r1 == 0 goto +13 <LBB9_172>
    1315:	r4 = *(u32 *)(r10 - 4)
    1316:	r5 = *(u64 *)(r10 - 256)
    1317:	r5 |= 20
    1318:	r5 &= 65535
    1319:	r1 = *(u64 *)(r10 - 168)
; if ((entry = map_lookup_elem(map, tuple))) {
    1320:	r2 = r9
    1321:	r3 = *(u64 *)(r10 - 232)
    1322:	call 11
    1323:	r7 = 4294967142 ll
    1325:	r0 <<= 32
    1326:	r0 s>>= 32
    1327:	if r0 s< 0 goto +59 <LBB9_175>

LBB9_172:
    1328:	r9 = *(u64 *)(r10 - 168)
    1329:	r7 = *(u32 *)(r9 + 0)
    1330:	r1 = r9
    1331:	call 34
; cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
    1332:	*(u32 *)(r10 - 92) = r0
    1333:	r1 = 269486339
    1334:	*(u32 *)(r10 - 96) = r1
; uint32_t hash = get_hash_recalc(skb);
    1335:	r1 = *(u64 *)(r10 - 200)
    1336:	*(u32 *)(r10 - 80) = r1
; struct debug_msg msg = {
    1337:	*(u32 *)(r10 - 88) = r7
    1338:	if r7 < 128 goto +1 <LBB9_174>
    1339:	r7 = 128

LBB9_174:
    1340:	*(u32 *)(r10 - 84) = r7
    1341:	r1 = 0
    1342:	*(u32 *)(r10 - 76) = r1
    1343:	r7 <<= 32
    1344:	r1 = 4294967295 ll
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1346:	r7 |= r1
    1347:	r4 = r10
    1348:	r4 += -96
    1349:	r1 = r9
    1350:	r2 = 0 ll
    1352:	r3 = r7
; return !entry->rx_closing || !entry->tx_closing;
    1353:	r5 = 24
    1354:	call 25
    1355:	r6 = *(u8 *)(r10 - 8)
    1356:	r7 = *(u32 *)(r10 - 16)
; if (ct_entry_alive(entry)) {
    1357:	r8 = *(u32 *)(r10 - 12)
    1358:	r1 = r9
; if (tcp) {
    1359:	call 34
    1360:	*(u32 *)(r10 - 92) = r0
; entry->seen_non_syn |= !syn;
    1361:	r1 = 269494274
    1362:	*(u32 *)(r10 - 96) = r1
    1363:	*(u32 *)(r10 - 88) = r8
    1364:	*(u32 *)(r10 - 84) = r7
    1365:	*(u32 *)(r10 - 80) = r6
    1366:	r4 = r10
    1367:	r4 += -96
    1368:	r1 = r9
    1369:	r2 = 0 ll
    1371:	r3 = 4294967295 ll
; if (entry->seen_non_syn)
    1373:	r5 = 20
    1374:	call 25
    1375:	r2 = r10
    1376:	r2 += -16
; return ktime_get_ns();
    1377:	r3 = r10
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1378:	r3 += -40
; entry->lifetime = now + lifetime;
    1379:	r1 = 0 ll
; seen_flags |= *accumulated_flags;
    1381:	r4 = 0
    1382:	call 2
    1383:	r7 = r0
    1384:	r7 <<= 32
    1385:	r7 s>>= 63
    1386:	r7 &= -161

LBB9_175:
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1387:	r1 = r7
    1388:	r1 <<= 32
    1389:	r1 >>= 32
    1390:	r2 = 1
    1391:	if r1 == 2 goto +1 <LBB9_177>
    1392:	r2 = 0

LBB9_177:
    1393:	r1 >>= 31
    1394:	r1 |= r2
    1395:	r9 = *(u64 *)(r10 - 168)
    1396:	if r1 != 0 goto +41 <LBB9_180>
; *accumulated_flags = seen_flags;
    1397:	r6 = *(u32 *)(r9 + 56)
; *last_report = now;
    1398:	r1 = r9
    1399:	call 34
; ct_state->rev_nat_index = entry->rev_nat_index;
    1400:	*(u32 *)(r10 - 92) = r0
; if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
    1401:	r1 = 269488898
    1402:	*(u32 *)(r10 - 96) = r1
    1403:	*(u32 *)(r10 - 88) = r6
    1404:	r1 = 0
    1405:	*(u32 *)(r10 - 84) = r1
    1406:	*(u32 *)(r10 - 80) = r1
    1407:	r4 = r10
; skb->cb[CB_NAT46_STATE] = NAT46;
    1408:	r4 += -96
    1409:	r1 = r9
    1410:	r2 = 0 ll
; __sync_fetch_and_add(&entry->tx_packets, 1);
    1412:	r3 = 4294967295 ll
; __sync_fetch_and_add(&entry->tx_bytes, skb->len);
    1414:	r5 = 20
    1415:	call 25
    1416:	r3 = r10
    1417:	r3 += -152
    1418:	r1 = r9
    1419:	r2 = 6
; switch (action) {
    1420:	r4 = 6
    1421:	r5 = 0
    1422:	call 9
    1423:	r7 = 4294967155 ll
; ret = entry->rx_closing + entry->tx_closing;
    1425:	r0 <<= 32
    1426:	r0 s>>= 32
    1427:	if r0 s< 0 goto +10 <LBB9_180>
    1428:	r3 = r10
    1429:	r3 += -144
; if (unlikely(ret >= 1)) {
    1430:	r1 = r9
    1431:	r2 = 0
; entry->tx_closing = 0;
    1432:	r4 = 6
    1433:	r5 = 0
    1434:	call 9
    1435:	r0 <<= 32
; if (tcp) {
    1436:	r0 s>>= 32
    1437:	if r0 s> -1 goto +2 <LBB9_181>

LBB9_180:
    1438:	r6 = *(u64 *)(r10 - 184)
; entry->seen_non_syn |= !syn;
    1439:	goto +59 <LBB9_191>

LBB9_181:
    1440:	r1 = 1
    1441:	*(u32 *)(r9 + 52) = r1
    1442:	r6 = *(u64 *)(r10 - 184)
    1443:	goto +52 <LBB9_190>

LBB9_184:
    1444:	*(u64 *)(r10 - 88) = r7
    1445:	r1 = 1
    1446:	*(u64 *)(r10 - 96) = r1
    1447:	r2 = r10
    1448:	r2 += -40
    1449:	r3 = r10
; if (entry->seen_non_syn)
    1450:	r3 += -96
    1451:	r1 = 0 ll
    1453:	r4 = 0
; return ktime_get_ns();
    1454:	call 2

LBB9_185:
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1455:	r7 = *(u64 *)(r10 - 208)
; entry->lifetime = now + lifetime;
    1456:	r7 <<= 32
    1457:	r7 >>= 32
; seen_flags |= *accumulated_flags;
    1458:	if r7 == 0 goto +34 <LBB9_189>
    1459:	r1 = *(u32 *)(r9 + 0)
    1460:	*(u64 *)(r10 - 176) = r1
    1461:	r1 = r9
    1462:	call 34
    1463:	*(u32 *)(r10 - 92) = r0
    1464:	r1 = 269484036
    1465:	*(u32 *)(r10 - 96) = r1
    1466:	*(u32 *)(r10 - 80) = r6
    1467:	r1 = 2
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1468:	*(u32 *)(r10 - 76) = r1
    1469:	r1 = 4112
    1470:	*(u16 *)(r10 - 72) = r1
    1471:	*(u8 *)(r10 - 70) = r8
    1472:	r1 = 0
    1473:	*(u8 *)(r10 - 69) = r1
    1474:	r1 = *(u64 *)(r10 - 160)
    1475:	*(u32 *)(r10 - 68) = r1
    1476:	r1 = *(u64 *)(r10 - 176)
    1477:	*(u32 *)(r10 - 88) = r1
; *accumulated_flags = seen_flags;
    1478:	if r7 < r1 goto +1 <LBB9_188>
; *last_report = now;
    1479:	r7 = r1

LBB9_188:
    1480:	*(u32 *)(r10 - 84) = r7
    1481:	r7 <<= 32
    1482:	r1 = 4294967295 ll
; if (dir == CT_INGRESS)
    1484:	r7 |= r1
    1485:	r4 = r10
; return !entry->rx_closing || !entry->tx_closing;
    1486:	r4 += -96
; if (ct_entry_alive(entry))
    1487:	r1 = r9
; return ktime_get_ns();
    1488:	r2 = 0 ll
; entry->lifetime = now + lifetime;
    1490:	r3 = r7
    1491:	r5 = 32
    1492:	call 25

LBB9_189:
; seen_flags |= *accumulated_flags;
    1493:	r7 = 0
    1494:	r1 = *(u32 *)(r9 + 52)
    1495:	if r1 == 0 goto +3 <LBB9_191>

LBB9_190:
    1496:	r2 = 0
    1497:	call 23
    1498:	r7 = r0

LBB9_191:
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1499:	r1 = r7
    1500:	r1 <<= 32
    1501:	r1 >>= 32
    1502:	r2 = 1
    1503:	if r1 == 2 goto +1 <LBB9_193>
    1504:	r2 = 0

LBB9_193:
    1505:	r1 >>= 31
    1506:	r1 |= r2
    1507:	if r1 == 0 goto +48 <LBB9_198>
; *accumulated_flags = seen_flags;
    1508:	r1 = 2
; *last_report = now;
    1509:	*(u32 *)(r9 + 48) = r1
; if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1510:	r1 = 4112
    1511:	*(u32 *)(r9 + 60) = r1
    1512:	r1 = *(u64 *)(r10 - 160)
    1513:	*(u32 *)(r9 + 64) = r1
    1514:	r6 <<= 16
    1515:	r6 |= 2
; if (dir == CT_INGRESS)
    1516:	*(u32 *)(r9 + 52) = r6
    1517:	*(u32 *)(r9 + 56) = r7
    1518:	r8 = *(u32 *)(r9 + 0)
; return !entry->rx_closing || !entry->tx_closing;
    1519:	r1 = 0
; if (ct_entry_alive(entry))
    1520:	*(u64 *)(r10 - 88) = r1
; return ktime_get_ns();
    1521:	*(u64 *)(r10 - 96) = r1
    1522:	r1 = 256
; return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
    1523:	*(u64 *)(r10 - 136) = r1
; entry->lifetime = now + lifetime;
    1524:	r7 = -r7
    1525:	*(u8 *)(r10 - 136) = r7
    1526:	r2 = r10
; seen_flags |= *accumulated_flags;
    1527:	r2 += -136
    1528:	r1 = 0 ll
    1530:	call 1
    1531:	if r0 == 0 goto +7 <LBB9_196>
    1532:	r1 = *(u64 *)(r0 + 0)
; if (*last_report + CT_REPORT_INTERVAL < now ||
    1533:	r1 += 1
    1534:	*(u64 *)(r0 + 0) = r1
    1535:	r1 = *(u64 *)(r0 + 8)
    1536:	r1 += r8
    1537:	*(u64 *)(r0 + 8) = r1
    1538:	goto +11 <LBB9_197>

LBB9_196:
    1539:	*(u64 *)(r10 - 88) = r8
    1540:	r1 = 1
    1541:	*(u64 *)(r10 - 96) = r1
; *accumulated_flags = seen_flags;
    1542:	r2 = r10
; *last_report = now;
    1543:	r2 += -136
; skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
    1544:	r3 = r10
    1545:	r3 += -96
    1546:	r1 = 0 ll
; uint32_t hash = get_hash_recalc(skb);
    1548:	r4 = 0
; struct debug_msg msg = {
    1549:	call 2

LBB9_197:
    1550:	r1 = r9
    1551:	r2 = 0 ll
    1553:	r3 = 1
    1554:	call 12
    1555:	r7 = 2

LBB9_198:
; cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
    1556:	r0 = r7
    1557:	exit

LBB9_134:
; struct debug_msg msg = {
    1558:	r1 = *(u64 *)(r10 - 200)
    1559:	if r1 != 0 goto +15 <LBB9_199>
; static inline void cilium_dbg(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
    1560:	*(u16 *)(r10 - 36) = r8
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    1561:	r1 = 0
    1562:	*(u32 *)(r10 - 40) = r1
    1563:	*(u8 *)(r10 - 34) = r9
    1564:	r2 = r10
    1565:	r2 += -40
    1566:	r1 = 0 ll
    1568:	call 1
; if (conn_is_dns(tuple->dport))
    1569:	r2 = r0
    1570:	if r0 == 0 goto +4 <LBB9_199>
    1571:	r1 = 1
    1572:	lock *(u64 *)(r2 + 8) += r1
    1573:	r9 = *(u64 *)(r10 - 168)
    1574:	goto -528 <LBB9_137>

LBB9_199:
    1575:	r3 = 0
    1576:	r9 = *(u64 *)(r10 - 168)
    1577:	r1 = *(u32 *)(r9 + 56)
    1578:	r6 = *(u64 *)(r10 - 184)
    1579:	r7 = *(u64 *)(r10 - 216)
; void *data_end = (void *) (long) skb->data_end;
    1580:	r8 = *(u64 *)(r10 - 176)
; void *data = (void *) (long) skb->data;
    1581:	if r1 == 0 goto +1 <LBB9_140>
; if (data + ETH_HLEN + l3_len > data_end)
    1582:	goto -515 <LBB9_139>

LBB9_140:
    1583:	r1 = r9
    1584:	call 34
    1585:	*(u32 *)(r10 - 92) = r0
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1586:	r1 = 269485314
    1587:	*(u32 *)(r10 - 96) = r1
    1588:	*(u32 *)(r10 - 88) = r6
    1589:	r1 = 2
; addr->p4 &= GET_PREFIX(prefix);
    1590:	*(u32 *)(r10 - 84) = r1
; addr->p3 &= GET_PREFIX(prefix);
    1591:	r1 = 0
    1592:	*(u32 *)(r10 - 80) = r1
    1593:	r4 = r10
    1594:	r4 += -96
    1595:	r1 = r9
    1596:	r2 = 0 ll
; .ip6 = *addr,
    1598:	r3 = 4294967295 ll
    1600:	r5 = 20
    1601:	call 25
    1602:	r3 = 4294967163 ll
; return map_lookup_elem(map, &key);
    1604:	r1 = r8
    1605:	r1 |= 1
    1606:	if r1 == 3 goto -539 <LBB9_139>
    1607:	r7 = 4294967163 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1609:	if r8 != 1 goto -111 <LBB9_191>
    1610:	r1 = 0 ll
; .ip6 = *addr,
    1612:	r2 = *(u8 *)(r10 - 100)
; addr->p4 &= GET_PREFIX(prefix);
    1613:	if r2 == 6 goto +2 <LBB9_144>
; addr->p3 &= GET_PREFIX(prefix);
    1614:	r1 = 0 ll

LBB9_144:
    1616:	r2 = r10
    1617:	r2 += -112
    1618:	call 3
    1619:	r8 = r0
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1620:	r8 <<= 32
; return map_lookup_elem(map, &key);
    1621:	r8 s>>= 32
    1622:	r9 = *(u64 *)(r10 - 168)
    1623:	r6 = *(u64 *)(r10 - 184)
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1624:	if r8 s> -1 goto -126 <LBB9_191>
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1625:	r1 = r9
    1626:	call 34
    1627:	*(u32 *)(r10 - 92) = r0
; .ip6 = *addr,
    1628:	r1 = 269488642
    1629:	*(u32 *)(r10 - 96) = r1
; addr->p4 &= GET_PREFIX(prefix);
    1630:	r1 = 3
; addr->p3 &= GET_PREFIX(prefix);
    1631:	*(u32 *)(r10 - 88) = r1
    1632:	*(u32 *)(r10 - 84) = r8
    1633:	r1 = 0
    1634:	*(u32 *)(r10 - 80) = r1
    1635:	r4 = r10
    1636:	r4 += -96
; LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
    1637:	r1 = r9
; return map_lookup_elem(map, &key);
    1638:	r2 = 0 ll
    1640:	r3 = 4294967295 ll
; .lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
    1642:	r5 = 20
    1643:	call 25
    1644:	goto -146 <LBB9_191>
Disassembly of section 1/0x1010:
handle_policy:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r7 = *(u32 *)(r6 + 48)
       2:	r8 = *(u32 *)(r6 + 52)
       3:	r2 = *(u32 *)(r6 + 16)
       4:	if r2 == 8 goto +8 <LBB10_3>
; struct lb6_key key = {};
       5:	r1 = 4294967157 ll
       7:	if r2 != 56710 goto +12 <LBB10_5>
       8:	r1 = r6
       9:	r2 = 0 ll
; if (!tmp)
      11:	r3 = 12
      12:	goto +4 <LBB10_4>

LBB10_3:
      13:	r1 = r6
; tmp = a->p2 - b->p2;
      14:	r2 = 0 ll
      16:	r3 = 11

LBB10_4:
      17:	call 12
; tmp = a->p1 - b->p1;
      18:	r1 = 4294967156 ll

LBB10_5:
; if (!tmp)
      20:	r2 = 2
      21:	*(u32 *)(r6 + 48) = r2
; tmp = a->p2 - b->p2;
      22:	r2 = 4112
; else if (unlikely(!is_valid_gw_dst_mac(eth)))
      23:	*(u32 *)(r6 + 60) = r2
      24:	*(u32 *)(r6 + 64) = r8
      25:	r7 <<= 16
; tmp = a->p1 - b->p1;
      26:	r7 |= 2
; if (!tmp) {
      27:	*(u32 *)(r6 + 52) = r7
; tmp = a->p2 - b->p2;
      28:	*(u32 *)(r6 + 56) = r1
; if (!tmp) {
      29:	r7 = *(u32 *)(r6 + 0)
; tmp = a->p3 - b->p3;
      30:	r2 = 0
; if (!tmp)
      31:	*(u64 *)(r10 - 8) = r2
; tmp = a->p4 - b->p4;
      32:	*(u64 *)(r10 - 16) = r2
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r2 = 256
      34:	*(u64 *)(r10 - 24) = r2
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r1 = -r1
      36:	*(u8 *)(r10 - 24) = r1
; dst->p1 = src->p1;
      37:	r2 = r10
      38:	r2 += -24
; dst->p2 = src->p2;
      39:	r1 = 0 ll
; dst->p3 = src->p3;
      41:	call 1
      42:	if r0 == 0 goto +7 <LBB10_7>
; dst->p4 = src->p4;
      43:	r1 = *(u64 *)(r0 + 0)
      44:	r1 += 1
; dst->p1 = src->p1;
      45:	*(u64 *)(r0 + 0) = r1
      46:	r1 = *(u64 *)(r0 + 8)
; dst->p2 = src->p2;
      47:	r1 += r7
      48:	*(u64 *)(r0 + 8) = r1
; dst->p3 = src->p3;
      49:	goto +11 <LBB10_8>

LBB10_7:
      50:	*(u64 *)(r10 - 8) = r7
; dst->p4 = src->p4;
      51:	r1 = 1
      52:	*(u64 *)(r10 - 16) = r1
      53:	r2 = r10
      54:	r2 += -24
; __u8 nh = *nexthdr;
      55:	r3 = r10
; switch (nh) {
      56:	r3 += -16
      57:	r1 = 0 ll
      59:	r4 = 0
      60:	call 2

LBB10_8:
      61:	r1 = r6
      62:	r2 = 0 ll
      64:	r3 = 1
      65:	call 12
      66:	r0 = 2
      67:	exit
Disassembly of section 2/8:
tail_ipv6_to_ipv4:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r1 = 0
       2:	*(u32 *)(r10 - 64) = r1
       3:	*(u64 *)(r10 - 72) = r1
       4:	*(u64 *)(r10 - 80) = r1
; struct lb6_key key = {};
       5:	r1 = 8
       6:	*(u16 *)(r10 - 82) = r1
       7:	r3 = r10
       8:	r3 += -56
       9:	r1 = r6
; tmp = a->p1 - b->p1;
      10:	r2 = 14
; if (!tmp)
      11:	r4 = 40
      12:	call 26
      13:	r7 = 4294967162 ll
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	r0 <<= 32
      16:	r0 s>>= 32
      17:	if r0 s< 0 goto +218 <LBB11_40>
; tmp = a->p1 - b->p1;
      18:	r1 = *(u8 *)(r10 - 50)
; if (!tmp)
      19:	if r1 > 60 goto +11 <LBB11_4>
      20:	r2 = 1
      21:	r2 <<= r1
; tmp = a->p2 - b->p2;
      22:	r3 = 1155182100513554433 ll
      24:	r4 = r2
      25:	r4 &= r3
; tmp = a->p1 - b->p1;
      26:	if r4 != 0 goto +5 <LBB11_5>
; if (!tmp) {
      27:	r3 = 576478344489467904 ll
; if (!tmp) {
      29:	r2 &= r3
; tmp = a->p3 - b->p3;
      30:	if r2 != 0 goto +203 <LBB11_39>

LBB11_4:
; if (!tmp)
      31:	goto +96 <LBB11_25>

LBB11_5:
; tmp = a->p4 - b->p4;
      32:	r3 = r10
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r3 += -8
      34:	r7 = 2
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r1 = r6
      36:	r2 = 54
; dst->p1 = src->p1;
      37:	r4 = 2
      38:	call 26
; dst->p2 = src->p2;
      39:	r0 <<= 32
      40:	r0 s>>= 32
; dst->p3 = src->p3;
      41:	if r0 s< 0 goto +192 <LBB11_39>
      42:	r1 = *(u8 *)(r10 - 8)
; dst->p4 = src->p4;
      43:	if r1 == 51 goto +1 <LBB11_8>
      44:	r7 = 3

LBB11_8:
; dst->p1 = src->p1;
      45:	if r1 > 60 goto +11 <LBB11_11>
      46:	r2 = 1
; dst->p2 = src->p2;
      47:	r2 <<= r1
      48:	r3 = 1155182100513554433 ll
; dst->p3 = src->p3;
      50:	r4 = r2
; dst->p4 = src->p4;
      51:	r4 &= r3
      52:	if r4 != 0 goto +6 <LBB11_12>
      53:	r3 = 576478344489467904 ll
; __u8 nh = *nexthdr;
      55:	r2 &= r3
; switch (nh) {
      56:	if r2 != 0 goto +177 <LBB11_39>

LBB11_11:
      57:	*(u8 *)(r10 - 50) = r1
      58:	goto +175 <LBB11_39>

LBB11_12:
      59:	r8 = *(u8 *)(r10 - 7)
      60:	r8 <<= r7
      61:	r2 = r8
      62:	r2 += 62
      63:	r3 = r10
      64:	r3 += -8
      65:	r7 = 2
      66:	r1 = r6
      67:	r4 = 2
      68:	call 26
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r0 <<= 32
      70:	r0 s>>= 32
      71:	if r0 s< 0 goto +162 <LBB11_39>
      72:	r1 = *(u8 *)(r10 - 8)
      73:	if r1 == 51 goto +1 <LBB11_15>
      74:	r7 = 3

LBB11_15:
      75:	r2 = *(u8 *)(r10 - 7)
      76:	r2 <<= r7
      77:	r8 += r2
      78:	r8 += 56
      79:	if r1 > 60 goto +42 <LBB11_24>
; nh = opthdr.nexthdr;
      80:	r2 = 1
; if (nh == NEXTHDR_AUTH)
      81:	r2 <<= r1
      82:	r3 = 1155182100513554433 ll
      84:	r4 = r2
      85:	r4 &= r3
      86:	if r4 != 0 goto +5 <LBB11_18>
; switch (nh) {
      87:	r3 = 576478344489467904 ll
      89:	r2 &= r3
      90:	if r2 != 0 goto +143 <LBB11_39>
      91:	goto +30 <LBB11_24>

LBB11_18:
      92:	r2 = r8
      93:	r2 += 14
      94:	r3 = r10
      95:	r3 += -8
      96:	r7 = 2
      97:	r1 = r6
      98:	r4 = 2
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	call 26
     100:	r0 <<= 32
     101:	r0 s>>= 32
     102:	if r0 s< 0 goto +131 <LBB11_39>
     103:	r1 = *(u8 *)(r10 - 8)
     104:	if r1 == 51 goto +1 <LBB11_21>
     105:	r7 = 3

LBB11_21:
     106:	r2 = *(u8 *)(r10 - 7)
     107:	r2 <<= r7
     108:	r8 += r2
     109:	r8 += 8
; nh = opthdr.nexthdr;
     110:	if r1 > 60 goto +11 <LBB11_24>
; if (nh == NEXTHDR_AUTH)
     111:	r2 = 1
     112:	r2 <<= r1
     113:	r3 = 1155182100513554433 ll
     115:	r4 = r2
     116:	r4 &= r3
     117:	if r4 != 0 goto +109 <LBB11_38>
; switch (nh) {
     118:	r3 = 576478344489467904 ll
     120:	r2 &= r3
     121:	if r2 != 0 goto +112 <LBB11_39>

LBB11_24:
     122:	*(u8 *)(r10 - 50) = r1
     123:	r7 = 4294967140 ll
     125:	r8 <<= 32
     126:	r8 >>= 32
     127:	if r8 != 40 goto +108 <LBB11_40>

LBB11_25:
     128:	r2 = 270544960
     129:	*(u32 *)(r10 - 68) = r2
     130:	r2 = 69
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	*(u8 *)(r10 - 80) = r2
     132:	r2 = *(u32 *)(r10 - 20)
     133:	*(u32 *)(r10 - 64) = r2
     134:	r2 = *(u8 *)(r10 - 49)
     135:	*(u8 *)(r10 - 72) = r2
     136:	r2 = 1
     137:	if r1 == 58 goto +1 <LBB11_27>
     138:	r2 = r1

LBB11_27:
     139:	*(u8 *)(r10 - 71) = r2
     140:	r1 = *(u16 *)(r10 - 52)
     141:	r1 = be16 r1
; nh = opthdr.nexthdr;
     142:	r1 += 20
; if (nh == NEXTHDR_AUTH)
     143:	r1 = be16 r1
     144:	*(u16 *)(r10 - 78) = r1
     145:	r3 = r10
     146:	r3 += -80
     147:	r1 = 0
     148:	r2 = 0
     149:	r4 = 20
; switch (nh) {
     150:	r5 = 0
     151:	call 28
     152:	r8 = r0
     153:	r1 = r6
     154:	r2 = 8
     155:	r3 = 0
     156:	call 31
     157:	r7 = 4294967155 ll
     159:	r0 <<= 32
     160:	r0 s>>= 32
     161:	if r0 s< 0 goto +74 <LBB11_40>
     162:	r3 = r10
; *nexthdr = nh;
     163:	r3 += -80
; dst->p1 = src->p1;
     164:	r1 = r6
     165:	r2 = 14
; dst->p2 = src->p2;
     166:	r4 = 20
     167:	r5 = 0
; dst->p3 = src->p3;
     168:	call 9
     169:	r0 <<= 32
; dst->p4 = src->p4;
     170:	r0 s>>= 32
     171:	if r0 s< 0 goto +64 <LBB11_40>
     172:	r3 = r10
     173:	r3 += -82
     174:	r1 = r6
; switch (nexthdr) {
     175:	r2 = 12
     176:	r4 = 2
     177:	r5 = 0
     178:	call 9
     179:	r0 <<= 32
     180:	r0 s>>= 32
     181:	if r0 s< 0 goto +54 <LBB11_40>
     182:	r1 = r6
     183:	r2 = 24
     184:	r3 = 0
; }
     185:	r4 = r8
     186:	r5 = 0
; switch (nexthdr) {
     187:	call 10
     188:	r7 = 4294967143 ll
     190:	r0 <<= 32
     191:	r0 s>>= 32
     192:	if r0 s< 0 goto +43 <LBB11_40>
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r7 = r10
     194:	r7 += -32
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	r1 = *(u8 *)(r10 - 50)
     196:	if r1 != 58 goto +112 <LBB11_49>
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     197:	r1 = 0
     198:	*(u64 *)(r10 - 8) = r1
     199:	r3 = r10
     200:	r3 += -16
     201:	r1 = r6
     202:	r2 = 34
     203:	r4 = 8
; if (IS_ERR(ret))
     204:	call 26
     205:	r8 = 4294967162 ll
     207:	r0 <<= 32
     208:	r0 s>>= 32
     209:	if r0 s< 0 goto +197 <LBB11_75>
     210:	r1 = *(u16 *)(r10 - 14)
     211:	*(u16 *)(r10 - 6) = r1
     212:	r8 = 4294967150 ll
; if (IS_ERR(ret)) {
     214:	r1 = *(u8 *)(r10 - 16)
     215:	if r1 s> 3 goto +115 <LBB11_51>
     216:	if r1 == 1 goto +122 <LBB11_55>
     217:	if r1 == 2 goto +157 <LBB11_69>
     218:	r8 = 4294967150 ll
     220:	if r1 == 3 goto +1 <LBB11_37>
     221:	goto +185 <LBB11_75>

LBB11_37:
     222:	r1 = 11
     223:	*(u8 *)(r10 - 8) = r1
     224:	r1 = *(u8 *)(r10 - 15)
     225:	*(u8 *)(r10 - 7) = r1
     226:	goto +156 <LBB11_73>

LBB11_38:
     227:	r8 += 14
; if (ret == DROP_UNKNOWN_L4)
     228:	r3 = r10
     229:	r3 += -8
     230:	r1 = r6
     231:	r2 = r8
     232:	r4 = 2
     233:	call 26

LBB11_39:
     234:	r7 = 4294967140 ll

LBB11_40:
     236:	r1 = r7
     237:	r1 <<= 32
     238:	r1 >>= 32
     239:	r2 = 1
     240:	if r1 == 2 goto +1 <LBB11_42>
; if (key->dport) {
     241:	r2 = 0

LBB11_42:
     242:	r1 >>= 31
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r1 |= r2
; uint32_t hash = get_hash_recalc(skb);
     244:	if r1 == 0 goto +28 <LBB11_45>
     245:	r1 = 131072
; struct debug_msg msg = {
     246:	*(u32 *)(r6 + 52) = r1
     247:	r1 = 2
     248:	*(u32 *)(r6 + 48) = r1
     249:	*(u32 *)(r6 + 56) = r7
     250:	r1 = 0
     251:	*(u32 *)(r6 + 60) = r1
     252:	*(u32 *)(r6 + 64) = r1
     253:	r8 = *(u32 *)(r6 + 0)
     254:	*(u64 *)(r10 - 48) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	*(u64 *)(r10 - 56) = r1
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r1 = 512
     257:	*(u64 *)(r10 - 80) = r1
     258:	r7 = -r7
     259:	*(u8 *)(r10 - 80) = r7
     260:	r2 = r10
     261:	r2 += -80
     262:	r1 = 0 ll
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	call 1
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	if r0 == 0 goto +202 <LBB11_85>
     266:	r1 = *(u64 *)(r0 + 0)
     267:	r1 += 1
; if (svc && svc->count != 0)
     268:	*(u64 *)(r0 + 0) = r1
     269:	r1 = *(u64 *)(r0 + 8)
     270:	r1 += r8
     271:	*(u64 *)(r0 + 8) = r1
     272:	goto +206 <LBB11_86>

LBB11_45:
     273:	r7 = *(u32 *)(r6 + 0)
; key->dport = 0;
     274:	r8 = *(u32 *)(r6 + 36)
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r1 = r6
; uint32_t hash = get_hash_recalc(skb);
     276:	call 34
     277:	*(u32 *)(r10 - 52) = r0
; struct debug_msg msg = {
     278:	r1 = 269485827
     279:	*(u32 *)(r10 - 56) = r1
     280:	*(u32 *)(r10 - 40) = r8
     281:	r1 = 0
     282:	*(u32 *)(r10 - 36) = r1
     283:	*(u32 *)(r10 - 48) = r7
     284:	if r7 < 128 goto +1 <LBB11_47>
     285:	r7 = 128

LBB11_47:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	*(u32 *)(r10 - 44) = r7
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r7 <<= 32
     288:	r1 = 4294967295 ll
     290:	r7 |= r1
     291:	r4 = r10
     292:	r4 += -56
     293:	r1 = r6
     294:	r2 = 0 ll
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	r3 = r7
     297:	r5 = 24
     298:	call 25
; if (svc && svc->count != 0)
     299:	r1 = 1
     300:	*(u32 *)(r6 + 60) = r1
     301:	r1 = r6
     302:	r2 = 0 ll
     304:	r3 = 7
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     305:	call 12
     306:	r0 = 4294967156 ll

LBB11_48:
; uint32_t hash = get_hash_recalc(skb);
     308:	exit

LBB11_49:
; struct debug_msg msg = {
     309:	r8 = r10
     310:	r8 += -64
     311:	r3 = r10
     312:	r3 += -68
     313:	r1 = r10
     314:	r1 += -48
     315:	r2 = 16
     316:	r4 = 4
     317:	r5 = 0
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	call 28
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	r1 = r7
     320:	r2 = 16
     321:	r3 = r8
     322:	r4 = 4
     323:	r5 = r0
     324:	call 28
     325:	r8 = r0
     326:	r9 = 48
     327:	r1 = *(u8 *)(r10 - 71)
     328:	if r1 == 17 goto +114 <LBB11_76>
     329:	r9 = 16
     330:	goto +112 <LBB11_76>

LBB11_51:
     331:	if r1 == 4 goto +18 <LBB11_59>
     332:	if r1 == 128 goto +27 <LBB11_62>
; __u8 flags = tuple->flags;
     333:	r8 = 4294967150 ll
; union tcp_flags tcp_flags = { 0 };
     335:	if r1 == 129 goto +1 <LBB11_54>
     336:	goto +70 <LBB11_75>

LBB11_54:
; tuple->flags = TUPLE_F_SERVICE;
     337:	r1 = 0
     338:	goto +22 <LBB11_63>

LBB11_55:
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r1 = 3
     340:	*(u8 *)(r10 - 8) = r1
     341:	r8 = 4294967151 ll
     343:	r1 = *(u8 *)(r10 - 15)
     344:	if r1 s> 1 goto +21 <LBB11_64>
; switch (tuple->nexthdr) {
     345:	if r1 == 0 goto +27 <LBB11_67>
     346:	if r1 == 1 goto +1 <LBB11_58>
     347:	goto +59 <LBB11_75>

LBB11_58:
     348:	r1 = 10
     349:	goto +24 <LBB11_68>

LBB11_59:
     350:	r1 = *(u8 *)(r10 - 15)
; __u8 type;
     351:	if r1 == 1 goto +113 <LBB11_84>
     352:	r8 = 4294967151 ll
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     354:	if r1 != 0 goto +52 <LBB11_75>
     355:	r1 = 12
     356:	*(u16 *)(r10 - 8) = r1
     357:	r8 = 4294967150 ll
     359:	goto +47 <LBB11_75>

LBB11_62:
     360:	r1 = 8

LBB11_63:
     361:	*(u8 *)(r10 - 8) = r1
; tuple->dport = 0;
     362:	r1 = *(u16 *)(r10 - 12)
     363:	*(u16 *)(r10 - 4) = r1
; tuple->sport = 0;
     364:	r1 = *(u16 *)(r10 - 10)
     365:	goto +16 <LBB11_72>

LBB11_64:
     366:	r2 = r1
; switch (type) {
     367:	r2 += -2
     368:	if r2 < 2 goto +4 <LBB11_67>
     369:	if r1 == 4 goto +1 <LBB11_66>
     370:	goto +36 <LBB11_75>

LBB11_66:
     371:	r1 = 3
     372:	goto +1 <LBB11_68>

LBB11_67:
; tuple->dport = ICMPV6_ECHO_REQUEST;
     373:	r1 = 1

LBB11_68:
     374:	*(u8 *)(r10 - 7) = r1

LBB11_69:
     375:	r1 = 1027
     376:	*(u16 *)(r10 - 8) = r1
     377:	r1 = *(u32 *)(r10 - 12)
     378:	if r1 == 0 goto +2 <LBB11_71>
     379:	r1 >>= 16
     380:	goto +1 <LBB11_72>

LBB11_71:
     381:	r1 = 56325

LBB11_72:
; if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
     382:	*(u16 *)(r10 - 2) = r1

LBB11_73:
     383:	r3 = r10
     384:	r3 += -8
     385:	r9 = 0
     386:	r1 = r6
     387:	r2 = 34
     388:	r4 = 8
     389:	r5 = 0
     390:	call 9
     391:	r8 = 4294967155 ll
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     393:	r0 <<= 32
     394:	r0 s>>= 32
     395:	if r0 s< 0 goto +11 <LBB11_75>
     396:	*(u16 *)(r10 - 14) = r9
     397:	*(u16 *)(r10 - 6) = r9
     398:	r1 = r10
; if (unlikely(tcp_flags.rst || tcp_flags.fin))
     399:	r1 += -16
     400:	r3 = r10
     401:	r3 += -8
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     402:	r2 = 8
     403:	r4 = 8
     404:	r5 = 0
     405:	call 28
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     406:	r8 = r0

LBB11_75:
     407:	r1 = *(u16 *)(r10 - 52)
     408:	r1 = be16 r1
     409:	r1 = be32 r1
     410:	*(u32 *)(r10 - 8) = r1
     411:	r1 = 973078528
     412:	*(u32 *)(r10 - 16) = r1
     413:	r3 = r10
     414:	r3 += -48
     415:	r9 = 16
     416:	r1 = 0
     417:	r2 = 0
     418:	r4 = 16
     419:	r5 = 0
; tuple->flags |= TUPLE_F_RELATED;
     420:	call 28
     421:	r1 = 0
     422:	r2 = 0
     423:	r3 = r7
; break;
     424:	r4 = 16
     425:	r5 = r0
; tuple->sport = type;
     426:	call 28
     427:	r3 = r10
     428:	r3 += -8
     429:	r1 = 0
     430:	r2 = 0
; if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
     431:	r4 = 4
     432:	r5 = r0
     433:	call 28
     434:	r3 = r10
     435:	r3 += -16
     436:	r1 = 0
     437:	r2 = 0
     438:	r4 = 4
     439:	r5 = r0
     440:	call 28
     441:	r8 -= r0
     442:	r1 = *(u8 *)(r10 - 71)

LBB11_76:
; cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
     443:	r7 = 4294967154 ll
     445:	if r1 s> 16 goto +4 <LBB11_79>
     446:	if r1 == 1 goto +7 <LBB11_82>
     447:	r2 = 50
     448:	if r1 == 6 goto +6 <LBB11_83>
     449:	goto -214 <LBB11_40>

LBB11_79:
     450:	if r1 == 58 goto +3 <LBB11_82>
     451:	if r1 != 17 goto -216 <LBB11_40>
     452:	r2 = 40
     453:	goto +1 <LBB11_83>

LBB11_82:
     454:	r2 = 36

LBB11_83:
     455:	r1 = r6
     456:	r3 = 0
     457:	r4 = r8
     458:	r5 = r9
     459:	call 11
     460:	r7 = r0
     461:	r7 <<= 32
     462:	r7 s>>= 63
     463:	r7 &= -154
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     464:	goto -229 <LBB11_40>

LBB11_84:
     465:	r1 = 515
     466:	*(u16 *)(r10 - 8) = r1
     467:	goto -61 <LBB11_75>

LBB11_85:
     468:	*(u64 *)(r10 - 48) = r8
     469:	r1 = 1
     470:	*(u64 *)(r10 - 56) = r1
; uint32_t hash = get_hash_recalc(skb);
     471:	r2 = r10
     472:	r2 += -80
; struct debug_msg msg = {
     473:	r3 = r10
     474:	r3 += -56
     475:	r1 = 0 ll
     477:	r4 = 0
     478:	call 2

LBB11_86:
; (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
     479:	r1 = r6
     480:	r2 = 0 ll
     482:	r3 = 1
     483:	call 12
     484:	r0 = 2
     485:	goto -178 <LBB11_48>
Disassembly of section 2/9:
tail_ipv4_to_ipv6:
; {
       0:	r6 = r1
; union macaddr router_mac = NODE_MAC;
       1:	r7 = 4294967162 ll
       3:	r1 = *(u32 *)(r6 + 80)
       4:	r8 = *(u32 *)(r6 + 76)
; struct lb6_key key = {};
       5:	r2 = r8
       6:	r2 += 34
       7:	if r2 > r1 goto +270 <LBB12_52>
       8:	r1 = 0
       9:	*(u64 *)(r10 - 24) = r1
; tmp = a->p1 - b->p1;
      10:	*(u64 *)(r10 - 32) = r1
; if (!tmp)
      11:	*(u64 *)(r10 - 40) = r1
      12:	*(u64 *)(r10 - 48) = r1
      13:	*(u64 *)(r10 - 56) = r1
; tmp = a->p2 - b->p2;
      14:	r1 = 56710
; if (unlikely(!is_valid_lxc_src_mac(eth)))
      15:	*(u16 *)(r10 - 82) = r1
      16:	r3 = r10
      17:	r3 += -80
; tmp = a->p1 - b->p1;
      18:	r1 = r6
; if (!tmp)
      19:	r2 = 14
      20:	r4 = 20
      21:	call 26
; tmp = a->p2 - b->p2;
      22:	r7 = 4294967162 ll
      24:	r0 <<= 32
      25:	r0 s>>= 32
; tmp = a->p1 - b->p1;
      26:	if r0 s< 0 goto +251 <LBB12_52>
; if (!tmp) {
      27:	r7 = 4294967140 ll
; if (!tmp) {
      29:	r1 = *(u8 *)(r8 + 14)
; tmp = a->p3 - b->p3;
      30:	r1 &= 15
; if (!tmp)
      31:	if r1 != 5 goto +246 <LBB12_52>
; tmp = a->p4 - b->p4;
      32:	r1 = 58
; return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
      33:	r2 = *(u8 *)(r10 - 71)
      34:	if r2 == 1 goto +1 <LBB12_5>
; else if (unlikely(!is_valid_lxc_src_ip(ip6)))
      35:	r1 = r2

LBB12_5:
      36:	r2 = 96
; dst->p1 = src->p1;
      37:	*(u8 *)(r10 - 56) = r2
      38:	r2 = 655360
; dst->p2 = src->p2;
      39:	*(u32 *)(r10 - 40) = r2
      40:	r2 = *(u32 *)(r10 - 68)
; dst->p3 = src->p3;
      41:	*(u32 *)(r10 - 36) = r2
      42:	r2 = 61374
; dst->p4 = src->p4;
      43:	*(u64 *)(r10 - 48) = r2
      44:	*(u64 *)(r10 - 32) = r2
; dst->p1 = src->p1;
      45:	r2 = -4863213592620564480 ll
; dst->p2 = src->p2;
      47:	*(u64 *)(r10 - 24) = r2
      48:	r2 = *(u8 *)(r10 - 72)
; dst->p3 = src->p3;
      49:	*(u8 *)(r10 - 49) = r2
      50:	*(u8 *)(r10 - 50) = r1
; dst->p4 = src->p4;
      51:	r1 = *(u16 *)(r10 - 78)
      52:	r1 = be16 r1
      53:	r2 = *(u8 *)(r10 - 80)
      54:	r2 <<= 2
; __u8 nh = *nexthdr;
      55:	r2 &= 60
; switch (nh) {
      56:	r1 -= r2
      57:	r1 = be16 r1
      58:	*(u16 *)(r10 - 52) = r1
      59:	r1 = r6
      60:	r2 = 56710
      61:	r3 = 0
      62:	call 31
      63:	r7 = 4294967155 ll
      65:	r0 <<= 32
      66:	r0 s>>= 32
      67:	if r0 s< 0 goto +210 <LBB12_52>
      68:	r3 = r10
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      69:	r3 += -56
      70:	r1 = r6
      71:	r2 = 14
      72:	r4 = 40
      73:	r5 = 0
      74:	call 9
      75:	r0 <<= 32
      76:	r0 s>>= 32
      77:	if r0 s< 0 goto +200 <LBB12_52>
      78:	r3 = r10
      79:	r3 += -82
; nh = opthdr.nexthdr;
      80:	r1 = r6
; if (nh == NEXTHDR_AUTH)
      81:	r2 = 12
      82:	r4 = 2
      83:	r5 = 0
      84:	call 9
      85:	r0 <<= 32
      86:	r0 s>>= 32
; switch (nh) {
      87:	if r0 s< 0 goto +190 <LBB12_52>
      88:	r7 = r10
      89:	r7 += -48
      90:	r1 = *(u8 *)(r10 - 71)
      91:	if r1 != 1 goto +35 <LBB12_18>
      92:	r1 = 0
      93:	*(u64 *)(r10 - 16) = r1
      94:	r3 = r10
      95:	r3 += -8
      96:	r1 = r6
      97:	r2 = 54
      98:	r4 = 8
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      99:	call 26
     100:	r5 = 4294967162 ll
     102:	r0 <<= 32
     103:	r0 s>>= 32
     104:	if r0 s< 0 goto +118 <LBB12_43>
     105:	r1 = *(u16 *)(r10 - 6)
     106:	*(u16 *)(r10 - 14) = r1
     107:	r5 = 4294967152 ll
     109:	r1 = *(u8 *)(r10 - 8)
; nh = opthdr.nexthdr;
     110:	if r1 s> 7 goto +36 <LBB12_20>
; if (nh == NEXTHDR_AUTH)
     111:	if r1 == 0 goto +40 <LBB12_24>
     112:	if r1 == 3 goto +1 <LBB12_13>
     113:	goto +109 <LBB12_43>

LBB12_13:
     114:	r1 = 1
     115:	*(u8 *)(r10 - 16) = r1
     116:	r5 = 4294967153 ll
; switch (nh) {
     118:	r1 = *(u8 *)(r10 - 7)
     119:	if r1 s> 3 goto +46 <LBB12_29>
     120:	if r1 < 2 goto +55 <LBB12_33>
     121:	if r1 == 2 goto +69 <LBB12_38>
     122:	if r1 == 3 goto +1 <LBB12_17>
     123:	goto +99 <LBB12_43>

LBB12_17:
     124:	r1 = 4
     125:	*(u8 *)(r10 - 15) = r1
     126:	goto +72 <LBB12_41>

LBB12_18:
     127:	r1 = r10
     128:	r1 += -68
     129:	r2 = 4
     130:	r3 = r7
; if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     131:	r4 = 16
     132:	r5 = 0
     133:	call 28
     134:	r1 = r10
     135:	r1 += -64
     136:	r3 = r10
     137:	r3 += -32
     138:	r2 = 4
     139:	r4 = 16
     140:	r5 = r0
     141:	call 28
; nh = opthdr.nexthdr;
     142:	r8 = 48
; if (nh == NEXTHDR_AUTH)
     143:	r1 = *(u8 *)(r10 - 71)
     144:	if r1 == 17 goto +111 <LBB12_44>
     145:	r8 = 16
     146:	goto +109 <LBB12_44>

LBB12_20:
     147:	if r1 == 12 goto +11 <LBB12_26>
     148:	if r1 == 11 goto +14 <LBB12_27>
     149:	if r1 != 8 goto +73 <LBB12_43>
; switch (nh) {
     150:	r1 = 128
     151:	goto +1 <LBB12_25>

LBB12_24:
     152:	r1 = 129

LBB12_25:
     153:	*(u8 *)(r10 - 16) = r1
     154:	r1 = *(u16 *)(r10 - 4)
     155:	*(u16 *)(r10 - 12) = r1
     156:	r1 = *(u16 *)(r10 - 2)
     157:	*(u16 *)(r10 - 10) = r1
     158:	goto +40 <LBB12_41>

LBB12_26:
     159:	r1 = 6
     160:	*(u32 *)(r10 - 12) = r1
     161:	r1 = 4
     162:	goto +1 <LBB12_28>

LBB12_27:
; *nexthdr = nh;
     163:	r1 = 3

LBB12_28:
; dst->p1 = src->p1;
     164:	*(u8 *)(r10 - 16) = r1
     165:	goto +33 <LBB12_41>

LBB12_29:
; dst->p2 = src->p2;
     166:	if r1 > 13 goto +15 <LBB12_35>
     167:	r2 = 1
; dst->p3 = src->p3;
     168:	r2 <<= r1
     169:	r3 = r2
; dst->p4 = src->p4;
     170:	r3 &= 6592
     171:	if r3 != 0 goto +4 <LBB12_33>
     172:	r2 &= 9728
     173:	if r2 != 0 goto +5 <LBB12_34>
     174:	if r1 == 5 goto +1 <LBB12_33>
; switch (nexthdr) {
     175:	goto +6 <LBB12_35>

LBB12_33:
     176:	r1 = 0
     177:	*(u8 *)(r10 - 15) = r1
     178:	goto +20 <LBB12_41>

LBB12_34:
     179:	r1 = 1
     180:	*(u8 *)(r10 - 15) = r1
     181:	goto +17 <LBB12_41>

LBB12_35:
     182:	if r1 == 4 goto +1 <LBB12_36>
     183:	goto +39 <LBB12_43>

LBB12_36:
     184:	r1 = 2
; }
     185:	*(u16 *)(r10 - 16) = r1
     186:	r1 = *(u16 *)(r10 - 2)
; switch (nexthdr) {
     187:	if r1 == 0 goto +8 <LBB12_39>
     188:	r1 = be16 r1
     189:	r1 = be32 r1
     190:	goto +7 <LBB12_40>

LBB12_38:
     191:	r1 = 6
     192:	*(u32 *)(r10 - 12) = r1
; ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
     193:	r1 = 260
     194:	*(u16 *)(r10 - 16) = r1
; return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
     195:	goto +3 <LBB12_41>

LBB12_39:
     196:	r1 = 3691315200 ll

LBB12_40:
; return skb_load_bytes(skb, off, port, sizeof(__be16));
     198:	*(u32 *)(r10 - 12) = r1

LBB12_41:
     199:	r3 = r10
     200:	r3 += -16
     201:	r8 = 0
     202:	r1 = r6
     203:	r2 = 54
; if (IS_ERR(ret))
     204:	r4 = 8
     205:	r5 = 0
     206:	call 9
     207:	r5 = 4294967155 ll
     209:	r0 <<= 32
     210:	r0 s>>= 32
     211:	if r0 s< 0 goto +11 <LBB12_43>
     212:	*(u16 *)(r10 - 14) = r8
     213:	*(u16 *)(r10 - 6) = r8
; if (IS_ERR(ret)) {
     214:	r1 = r10
     215:	r1 += -8
     216:	r3 = r10
     217:	r3 += -16
     218:	r2 = 8
     219:	r4 = 8
     220:	r5 = 0
     221:	call 28
     222:	r5 = r0

LBB12_43:
     223:	r1 = *(u16 *)(r10 - 52)
     224:	r1 = be16 r1
     225:	r1 = be32 r1
     226:	*(u32 *)(r10 - 8) = r1
     227:	r1 = 973078528
; if (ret == DROP_UNKNOWN_L4)
     228:	*(u32 *)(r10 - 16) = r1
     229:	r8 = 16
     230:	r1 = 0
     231:	r2 = 0
     232:	r3 = r7
     233:	r4 = 16
     234:	call 28
     235:	r3 = r10
     236:	r3 += -32
     237:	r1 = 0
     238:	r2 = 0
     239:	r4 = 16
     240:	r5 = r0
; if (key->dport) {
     241:	call 28
     242:	r3 = r10
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     243:	r3 += -8
; uint32_t hash = get_hash_recalc(skb);
     244:	r1 = 0
     245:	r2 = 0
; struct debug_msg msg = {
     246:	r4 = 4
     247:	r5 = r0
     248:	call 28
     249:	r3 = r10
     250:	r3 += -16
     251:	r1 = 0
     252:	r2 = 0
     253:	r4 = 4
     254:	r5 = r0
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     255:	call 28

LBB12_44:
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     256:	r7 = 4294967154 ll
     258:	r1 = *(u8 *)(r10 - 50)
     259:	if r1 s> 16 goto +4 <LBB12_47>
     260:	if r1 == 1 goto +7 <LBB12_50>
     261:	r2 = 70
     262:	if r1 == 6 goto +6 <LBB12_51>
     263:	goto +14 <LBB12_52>

LBB12_47:
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     264:	if r1 == 58 goto +3 <LBB12_50>
; svc = map_lookup_elem(&cilium_lb6_services, key);
     265:	if r1 != 17 goto +12 <LBB12_52>
     266:	r2 = 60
     267:	goto +1 <LBB12_51>

LBB12_50:
; if (svc && svc->count != 0)
     268:	r2 = 56

LBB12_51:
     269:	r1 = r6
     270:	r3 = 0
     271:	r4 = r0
     272:	r5 = r8
     273:	call 11
; key->dport = 0;
     274:	r7 = r0
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     275:	r7 <<= 32
; uint32_t hash = get_hash_recalc(skb);
     276:	r7 s>>= 63
     277:	r7 &= -154

LBB12_52:
; struct debug_msg msg = {
     278:	r1 = r7
     279:	r1 <<= 32
     280:	r1 >>= 32
     281:	r2 = 1
     282:	if r1 == 2 goto +1 <LBB12_54>
     283:	r2 = 0

LBB12_54:
     284:	r1 >>= 31
     285:	r1 |= r2
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     286:	if r1 == 0 goto +28 <LBB12_57>
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     287:	r1 = 131072
     288:	*(u32 *)(r6 + 52) = r1
     289:	r1 = 2
     290:	*(u32 *)(r6 + 48) = r1
     291:	*(u32 *)(r6 + 56) = r7
     292:	r1 = 0
     293:	*(u32 *)(r6 + 60) = r1
     294:	*(u32 *)(r6 + 64) = r1
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
     295:	r8 = *(u32 *)(r6 + 0)
; svc = map_lookup_elem(&cilium_lb6_services, key);
     296:	*(u64 *)(r10 - 48) = r1
     297:	*(u64 *)(r10 - 56) = r1
     298:	r1 = 256
; if (svc && svc->count != 0)
     299:	*(u64 *)(r10 - 80) = r1
     300:	r7 = -r7
     301:	*(u8 *)(r10 - 80) = r7
     302:	r2 = r10
     303:	r2 += -80
     304:	r1 = 0 ll
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     306:	call 1
; uint32_t hash = get_hash_recalc(skb);
     307:	if r0 == 0 goto +41 <LBB12_61>
     308:	r1 = *(u64 *)(r0 + 0)
; struct debug_msg msg = {
     309:	r1 += 1
     310:	*(u64 *)(r0 + 0) = r1
     311:	r1 = *(u64 *)(r0 + 8)
     312:	r1 += r8
     313:	*(u64 *)(r0 + 8) = r1
     314:	goto +45 <LBB12_62>

LBB12_57:
     315:	r7 = *(u32 *)(r6 + 0)
     316:	r8 = *(u32 *)(r6 + 36)
     317:	r1 = r6
; cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
     318:	call 34
; skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
     319:	*(u32 *)(r10 - 52) = r0
     320:	r1 = 269485571
     321:	*(u32 *)(r10 - 56) = r1
     322:	*(u32 *)(r10 - 40) = r8
     323:	r1 = 0
     324:	*(u32 *)(r10 - 36) = r1
     325:	*(u32 *)(r10 - 48) = r7
     326:	if r7 < 128 goto +1 <LBB12_59>
     327:	r7 = 128

LBB12_59:
     328:	*(u32 *)(r10 - 44) = r7
     329:	r7 <<= 32
     330:	r1 = 4294967295 ll
     332:	r7 |= r1
; __u8 flags = tuple->flags;
     333:	r4 = r10
; if (tuple->nexthdr == IPPROTO_TCP) {
     334:	r4 += -56
; union tcp_flags tcp_flags = { 0 };
     335:	r1 = r6
     336:	r2 = 0 ll
; tuple->flags = TUPLE_F_SERVICE;
     338:	r3 = r7
; ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
     339:	r5 = 24
     340:	call 25
     341:	r1 = r6
     342:	r2 = 0 ll
     344:	r3 = 12
; switch (tuple->nexthdr) {
     345:	call 12
     346:	r0 = 4294967156 ll

LBB12_60:
     348:	exit

LBB12_61:
     349:	*(u64 *)(r10 - 48) = r8
     350:	r1 = 1
; __u8 type;
     351:	*(u64 *)(r10 - 56) = r1
     352:	r2 = r10
; if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
     353:	r2 += -80
     354:	r3 = r10
     355:	r3 += -56
     356:	r1 = 0 ll
     358:	r4 = 0
     359:	call 2

LBB12_62:
     360:	r1 = r6
     361:	r2 = 0 ll
; tuple->dport = 0;
     363:	r3 = 1
; tuple->sport = 0;
     364:	call 12
     365:	r0 = 2
     366:	goto -19 <LBB12_60>
