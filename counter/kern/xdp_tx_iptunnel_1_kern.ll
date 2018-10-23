; ModuleID = 'kern/xdp_tx_iptunnel_1_kern.bc'
source_filename = "kern/xdp_tx_iptunnel_1_kern.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.vip = type { %union.anon.1, i16, i16, i8 }
%union.anon.1 = type { [4 x i32] }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, i32, i32 }
%struct.ipv6hdr = type { i8, [3 x i8], i16, i8, i8, %struct.in6_addr, %struct.in6_addr }
%struct.in6_addr = type { %union.anon.2 }
%union.anon.2 = type { [4 x i32] }

@rxcnt = global %struct.bpf_map_def { i32 6, i32 4, i32 8, i32 256, i32 0, i32 0, i32 0 }, section "maps", align 4
@vip2tnl = global %struct.bpf_map_def { i32 1, i32 24, i32 40, i32 256, i32 0, i32 0, i32 0 }, section "maps", align 4
@_license = global [4 x i8] c"GPL\00", section "license", align 1
@llvm.used = appending global [4 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @_xdp_tx_iptunnel to i8*), i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define i32 @_xdp_tx_iptunnel(%struct.xdp_md*) #0 section "xdp_tx_iptunnel" {
  %2 = alloca i32, align 4
  %3 = alloca %struct.vip, align 4
  %4 = alloca i32, align 4
  %5 = alloca %struct.vip, align 4
  %6 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1
  %7 = load i32, i32* %6, align 4, !tbaa !2
  %8 = zext i32 %7 to i64
  %9 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0
  %10 = load i32, i32* %9, align 4, !tbaa !7
  %11 = zext i32 %10 to i64
  %12 = inttoptr i64 %11 to %struct.ethhdr*
  %13 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %12, i64 1
  %14 = inttoptr i64 %8 to %struct.ethhdr*
  %15 = icmp ugt %struct.ethhdr* %13, %14
  br i1 %15, label %214, label %16

; <label>:16:                                     ; preds = %1
  %17 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %12, i64 0, i32 2
  %18 = load i16, i16* %17, align 1, !tbaa !8
  switch i16 %18, label %214 [
    i16 8, label %19
    i16 -8826, label %125
  ]

; <label>:19:                                     ; preds = %16
  %20 = inttoptr i64 %11 to i8*
  %21 = getelementptr i8, i8* %20, i64 14
  %22 = bitcast %struct.vip* %5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %22) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %22, i8 0, i64 24, i32 4, i1 false) #3
  %23 = getelementptr inbounds i8, i8* %20, i64 34
  %24 = bitcast i8* %23 to %struct.iphdr*
  %25 = inttoptr i64 %8 to %struct.iphdr*
  %26 = icmp ugt %struct.iphdr* %24, %25
  br i1 %26, label %123, label %27

; <label>:27:                                     ; preds = %19
  %28 = inttoptr i64 %8 to i8*
  %29 = getelementptr inbounds i8, i8* %20, i64 23
  %30 = load i8, i8* %29, align 1, !tbaa !11
  switch i8 %30, label %41 [
    i8 6, label %31
    i8 17, label %34
  ]

; <label>:31:                                     ; preds = %27
  %32 = getelementptr inbounds i8, i8* %20, i64 54
  %33 = icmp ugt i8* %32, %28
  br i1 %33, label %123, label %37

; <label>:34:                                     ; preds = %27
  %35 = getelementptr inbounds i8, i8* %20, i64 42
  %36 = icmp ugt i8* %35, %28
  br i1 %36, label %123, label %37

; <label>:37:                                     ; preds = %34, %31
  %38 = getelementptr inbounds i8, i8* %20, i64 36
  %39 = bitcast i8* %38 to i16*
  %40 = load i16, i16* %39, align 2, !tbaa !13
  br label %41

; <label>:41:                                     ; preds = %37, %27
  %42 = phi i16 [ 0, %27 ], [ %40, %37 ]
  %43 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 3
  store i8 %30, i8* %43, align 4, !tbaa !14
  %44 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 2
  store i16 2, i16* %44, align 2, !tbaa !16
  %45 = getelementptr inbounds i8, i8* %20, i64 30
  %46 = bitcast i8* %45 to i32*
  %47 = load i32, i32* %46, align 4, !tbaa !17
  %48 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 0, i32 0, i64 0
  store i32 %47, i32* %48, align 4, !tbaa !18
  %49 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 1
  store i16 %42, i16* %49, align 4, !tbaa !19
  %50 = getelementptr inbounds i8, i8* %20, i64 16
  %51 = bitcast i8* %50 to i16*
  %52 = load i16, i16* %51, align 2, !tbaa !20
  %53 = tail call i16 @llvm.bswap.i16(i16 %52) #3
  %54 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %22) #3
  %55 = icmp eq i8* %54, null
  br i1 %55, label %123, label %56

; <label>:56:                                     ; preds = %41
  %57 = getelementptr inbounds i8, i8* %54, i64 32
  %58 = bitcast i8* %57 to i16*
  %59 = load i16, i16* %58, align 4, !tbaa !21
  %60 = icmp eq i16 %59, 2
  br i1 %60, label %61, label %123

; <label>:61:                                     ; preds = %56
  %62 = bitcast %struct.xdp_md* %0 to i8*
  %63 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %62, i32 -20) #3
  %64 = icmp eq i32 %63, 0
  br i1 %64, label %65, label %123

; <label>:65:                                     ; preds = %61
  %66 = getelementptr i8, i8* %20, i64 20
  %67 = bitcast i8* %23 to %struct.ethhdr*
  %68 = icmp ugt %struct.ethhdr* %67, %14
  br i1 %68, label %123, label %69

; <label>:69:                                     ; preds = %65
  %70 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %12, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %70, i8* %66, i64 6, i32 1, i1 false) #3
  %71 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %12, i64 0, i32 0, i64 0
  %72 = getelementptr inbounds i8, i8* %54, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %71, i8* nonnull %72, i64 6, i32 1, i1 false) #3
  store i16 8, i16* %17, align 1, !tbaa !8
  store i8 69, i8* %21, align 4
  %73 = bitcast i8* %66 to i16*
  store i16 0, i16* %73, align 2, !tbaa !23
  store i8 4, i8* %29, align 1, !tbaa !11
  %74 = getelementptr inbounds i8, i8* %20, i64 24
  %75 = bitcast i8* %74 to i16*
  store i16 0, i16* %75, align 2, !tbaa !24
  %76 = getelementptr inbounds i8, i8* %20, i64 15
  store i8 0, i8* %76, align 1, !tbaa !25
  %77 = add i16 %53, 20
  %78 = call i16 @llvm.bswap.i16(i16 %77) #3
  store i16 %78, i16* %51, align 2, !tbaa !20
  %79 = getelementptr inbounds i8, i8* %54, i64 16
  %80 = bitcast i8* %79 to i32*
  %81 = load i32, i32* %80, align 4, !tbaa !18
  store i32 %81, i32* %46, align 4, !tbaa !17
  %82 = bitcast i8* %54 to i32*
  %83 = load i32, i32* %82, align 4, !tbaa !18
  %84 = getelementptr inbounds i8, i8* %20, i64 26
  %85 = bitcast i8* %84 to i32*
  store i32 %83, i32* %85, align 4, !tbaa !26
  %86 = getelementptr inbounds i8, i8* %20, i64 22
  store i8 8, i8* %86, align 4, !tbaa !27
  %87 = bitcast i8* %21 to i16*
  %88 = load i16, i16* %87, align 2, !tbaa !13
  %89 = zext i16 %88 to i32
  %90 = getelementptr inbounds i8, i8* %20, i64 18
  %91 = bitcast i8* %90 to i16*
  %92 = zext i16 %78 to i32
  %93 = add nuw nsw i32 %89, %92
  %94 = load i16, i16* %91, align 2, !tbaa !13
  %95 = zext i16 %94 to i32
  %96 = add nuw nsw i32 %93, %95
  %97 = bitcast i8* %86 to i16*
  %98 = load i16, i16* %97, align 2, !tbaa !13
  %99 = zext i16 %98 to i32
  %100 = add nuw nsw i32 %96, %99
  %101 = and i32 %83, 65535
  %102 = add nuw nsw i32 %100, %101
  %103 = lshr i32 %83, 16
  %104 = add nuw nsw i32 %102, %103
  %105 = and i32 %81, 65535
  %106 = add nuw nsw i32 %104, %105
  %107 = lshr i32 %81, 16
  %108 = add i32 %106, %107
  %109 = lshr i32 %108, 16
  %110 = add i32 %109, %108
  %111 = trunc i32 %110 to i16
  %112 = xor i16 %111, -1
  store i16 %112, i16* %75, align 2, !tbaa !24
  %113 = load i8, i8* %43, align 4, !tbaa !14
  %114 = zext i8 %113 to i32
  %115 = bitcast i32* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %115) #3
  store i32 %114, i32* %4, align 4, !tbaa !28
  %116 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %115) #3
  %117 = bitcast i8* %116 to i64*
  %118 = icmp eq i8* %116, null
  br i1 %118, label %122, label %119

; <label>:119:                                    ; preds = %69
  %120 = load i64, i64* %117, align 8, !tbaa !29
  %121 = add i64 %120, 1
  store i64 %121, i64* %117, align 8, !tbaa !29
  br label %122

; <label>:122:                                    ; preds = %119, %69
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %115) #3
  br label %123

; <label>:123:                                    ; preds = %19, %31, %34, %41, %56, %61, %65, %122
  %124 = phi i32 [ 3, %122 ], [ 1, %19 ], [ 2, %56 ], [ 2, %41 ], [ 1, %61 ], [ 1, %65 ], [ 1, %31 ], [ 1, %34 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %22) #3
  br label %214

; <label>:125:                                    ; preds = %16
  %126 = inttoptr i64 %11 to i8*
  %127 = bitcast %struct.vip* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %127) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %127, i8 0, i64 24, i32 4, i1 false) #3
  %128 = getelementptr inbounds i8, i8* %126, i64 54
  %129 = bitcast i8* %128 to %struct.ipv6hdr*
  %130 = inttoptr i64 %8 to %struct.ipv6hdr*
  %131 = icmp ugt %struct.ipv6hdr* %129, %130
  br i1 %131, label %212, label %132

; <label>:132:                                    ; preds = %125
  %133 = inttoptr i64 %8 to i8*
  %134 = getelementptr inbounds i8, i8* %126, i64 20
  %135 = load i8, i8* %134, align 2, !tbaa !31
  switch i8 %135, label %146 [
    i8 6, label %136
    i8 17, label %139
  ]

; <label>:136:                                    ; preds = %132
  %137 = getelementptr inbounds i8, i8* %126, i64 74
  %138 = icmp ugt i8* %137, %133
  br i1 %138, label %212, label %142

; <label>:139:                                    ; preds = %132
  %140 = getelementptr inbounds i8, i8* %126, i64 62
  %141 = icmp ugt i8* %140, %133
  br i1 %141, label %212, label %142

; <label>:142:                                    ; preds = %139, %136
  %143 = getelementptr inbounds i8, i8* %126, i64 56
  %144 = bitcast i8* %143 to i16*
  %145 = load i16, i16* %144, align 2, !tbaa !13
  br label %146

; <label>:146:                                    ; preds = %142, %132
  %147 = phi i16 [ 0, %132 ], [ %145, %142 ]
  %148 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 3
  store i8 %135, i8* %148, align 4, !tbaa !14
  %149 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 2
  store i16 10, i16* %149, align 2, !tbaa !16
  %150 = getelementptr inbounds i8, i8* %126, i64 38
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %127, i8* nonnull %150, i64 16, i32 4, i1 false) #3
  %151 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 1
  store i16 %147, i16* %151, align 4, !tbaa !19
  %152 = getelementptr inbounds i8, i8* %126, i64 18
  %153 = bitcast i8* %152 to i16*
  %154 = load i16, i16* %153, align 4, !tbaa !34
  %155 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %127) #3
  %156 = icmp eq i8* %155, null
  br i1 %156, label %212, label %157

; <label>:157:                                    ; preds = %146
  %158 = getelementptr inbounds i8, i8* %155, i64 32
  %159 = bitcast i8* %158 to i16*
  %160 = load i16, i16* %159, align 4, !tbaa !21
  %161 = icmp eq i16 %160, 10
  br i1 %161, label %162, label %212

; <label>:162:                                    ; preds = %157
  %163 = bitcast %struct.xdp_md* %0 to i8*
  %164 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %163, i32 -40) #3
  %165 = icmp eq i32 %164, 0
  br i1 %165, label %166, label %212

; <label>:166:                                    ; preds = %162
  %167 = load i32, i32* %9, align 4, !tbaa !7
  %168 = zext i32 %167 to i64
  %169 = inttoptr i64 %168 to i8*
  %170 = load i32, i32* %6, align 4, !tbaa !2
  %171 = zext i32 %170 to i64
  %172 = inttoptr i64 %168 to %struct.ethhdr*
  %173 = getelementptr i8, i8* %169, i64 14
  %174 = getelementptr i8, i8* %169, i64 40
  %175 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %172, i64 1
  %176 = inttoptr i64 %171 to %struct.ethhdr*
  %177 = icmp ugt %struct.ethhdr* %175, %176
  br i1 %177, label %212, label %178

; <label>:178:                                    ; preds = %166
  %179 = getelementptr inbounds i8, i8* %169, i64 54
  %180 = bitcast i8* %179 to %struct.ethhdr*
  %181 = icmp ugt %struct.ethhdr* %180, %176
  br i1 %181, label %212, label %182

; <label>:182:                                    ; preds = %178
  %183 = bitcast i8* %179 to %struct.ipv6hdr*
  %184 = inttoptr i64 %171 to %struct.ipv6hdr*
  %185 = icmp ugt %struct.ipv6hdr* %183, %184
  br i1 %185, label %212, label %186

; <label>:186:                                    ; preds = %182
  %187 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %172, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %187, i8* %174, i64 6, i32 1, i1 false) #3
  %188 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %172, i64 0, i32 0, i64 0
  %189 = getelementptr inbounds i8, i8* %155, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %188, i8* nonnull %189, i64 6, i32 1, i1 false) #3
  %190 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %172, i64 0, i32 2
  store i16 -8826, i16* %190, align 1, !tbaa !8
  store i8 96, i8* %173, align 4
  %191 = getelementptr inbounds i8, i8* %169, i64 15
  call void @llvm.memset.p0i8.i64(i8* nonnull %191, i8 0, i64 3, i32 1, i1 false) #3
  %192 = call i16 @llvm.bswap.i16(i16 %154) #3
  %193 = add i16 %192, 40
  %194 = call i16 @llvm.bswap.i16(i16 %193) #3
  %195 = getelementptr inbounds i8, i8* %169, i64 18
  %196 = bitcast i8* %195 to i16*
  store i16 %194, i16* %196, align 4, !tbaa !34
  %197 = getelementptr inbounds i8, i8* %169, i64 20
  store i8 41, i8* %197, align 2, !tbaa !31
  %198 = getelementptr inbounds i8, i8* %169, i64 21
  store i8 8, i8* %198, align 1, !tbaa !35
  %199 = getelementptr inbounds i8, i8* %169, i64 22
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %199, i8* nonnull %155, i64 16, i32 4, i1 false) #3
  %200 = getelementptr inbounds i8, i8* %169, i64 38
  %201 = getelementptr inbounds i8, i8* %155, i64 16
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %200, i8* nonnull %201, i64 16, i32 4, i1 false) #3
  %202 = load i8, i8* %148, align 4, !tbaa !14
  %203 = zext i8 %202 to i32
  %204 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %204) #3
  store i32 %203, i32* %2, align 4, !tbaa !28
  %205 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %204) #3
  %206 = bitcast i8* %205 to i64*
  %207 = icmp eq i8* %205, null
  br i1 %207, label %211, label %208

; <label>:208:                                    ; preds = %186
  %209 = load i64, i64* %206, align 8, !tbaa !29
  %210 = add i64 %209, 1
  store i64 %210, i64* %206, align 8, !tbaa !29
  br label %211

; <label>:211:                                    ; preds = %208, %186
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %204) #3
  br label %212

; <label>:212:                                    ; preds = %125, %136, %139, %146, %157, %162, %166, %178, %182, %211
  %213 = phi i32 [ 3, %211 ], [ 1, %125 ], [ 2, %157 ], [ 2, %146 ], [ 1, %162 ], [ 1, %182 ], [ 1, %178 ], [ 1, %166 ], [ 1, %136 ], [ 1, %139 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %127) #3
  br label %214

; <label>:214:                                    ; preds = %16, %1, %212, %123
  %215 = phi i32 [ %124, %123 ], [ %213, %212 ], [ 1, %1 ], [ 2, %16 ]
  ret i32 %215
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #1

; Function Attrs: nounwind readnone speculatable
declare i16 @llvm.bswap.i16(i16) #2

attributes #0 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { nounwind readnone speculatable }
attributes #3 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!2 = !{!3, !4, i64 4}
!3 = !{!"xdp_md", !4, i64 0, !4, i64 4, !4, i64 8, !4, i64 12, !4, i64 16}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = !{!3, !4, i64 0}
!8 = !{!9, !10, i64 12}
!9 = !{!"ethhdr", !5, i64 0, !5, i64 6, !10, i64 12}
!10 = !{!"short", !5, i64 0}
!11 = !{!12, !5, i64 9}
!12 = !{!"iphdr", !5, i64 0, !5, i64 0, !5, i64 1, !10, i64 2, !10, i64 4, !10, i64 6, !5, i64 8, !5, i64 9, !10, i64 10, !4, i64 12, !4, i64 16}
!13 = !{!10, !10, i64 0}
!14 = !{!15, !5, i64 20}
!15 = !{!"vip", !5, i64 0, !10, i64 16, !10, i64 18, !5, i64 20}
!16 = !{!15, !10, i64 18}
!17 = !{!12, !4, i64 16}
!18 = !{!5, !5, i64 0}
!19 = !{!15, !10, i64 16}
!20 = !{!12, !10, i64 2}
!21 = !{!22, !10, i64 32}
!22 = !{!"iptnl_info", !5, i64 0, !5, i64 16, !10, i64 32, !5, i64 34}
!23 = !{!12, !10, i64 6}
!24 = !{!12, !10, i64 10}
!25 = !{!12, !5, i64 1}
!26 = !{!12, !4, i64 12}
!27 = !{!12, !5, i64 8}
!28 = !{!4, !4, i64 0}
!29 = !{!30, !30, i64 0}
!30 = !{!"long long", !5, i64 0}
!31 = !{!32, !5, i64 6}
!32 = !{!"ipv6hdr", !5, i64 0, !5, i64 0, !5, i64 1, !10, i64 4, !5, i64 6, !5, i64 7, !33, i64 8, !33, i64 24}
!33 = !{!"in6_addr", !5, i64 0}
!34 = !{!32, !10, i64 4}
!35 = !{!32, !5, i64 7}
