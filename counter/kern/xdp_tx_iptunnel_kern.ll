; ModuleID = 'kern/xdp_tx_iptunnel_kern.bc'
source_filename = "kern/xdp_tx_iptunnel_kern.c"
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
  br i1 %15, label %235, label %16

; <label>:16:                                     ; preds = %1
  %17 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %12, i64 0, i32 2
  %18 = load i16, i16* %17, align 1, !tbaa !8
  switch i16 %18, label %235 [
    i16 8, label %19
    i16 -8826, label %146
  ]

; <label>:19:                                     ; preds = %16
  %20 = inttoptr i64 %11 to i8*
  %21 = bitcast %struct.vip* %5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %21) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %21, i8 0, i64 24, i32 4, i1 false) #3
  %22 = getelementptr inbounds i8, i8* %20, i64 34
  %23 = bitcast i8* %22 to %struct.iphdr*
  %24 = inttoptr i64 %8 to %struct.iphdr*
  %25 = icmp ugt %struct.iphdr* %23, %24
  br i1 %25, label %144, label %26

; <label>:26:                                     ; preds = %19
  %27 = inttoptr i64 %8 to i8*
  %28 = getelementptr inbounds i8, i8* %20, i64 23
  %29 = load i8, i8* %28, align 1, !tbaa !11
  switch i8 %29, label %40 [
    i8 6, label %30
    i8 17, label %33
  ]

; <label>:30:                                     ; preds = %26
  %31 = getelementptr inbounds i8, i8* %20, i64 54
  %32 = icmp ugt i8* %31, %27
  br i1 %32, label %144, label %36

; <label>:33:                                     ; preds = %26
  %34 = getelementptr inbounds i8, i8* %20, i64 42
  %35 = icmp ugt i8* %34, %27
  br i1 %35, label %144, label %36

; <label>:36:                                     ; preds = %33, %30
  %37 = getelementptr inbounds i8, i8* %20, i64 36
  %38 = bitcast i8* %37 to i16*
  %39 = load i16, i16* %38, align 2, !tbaa !13
  br label %40

; <label>:40:                                     ; preds = %36, %26
  %41 = phi i16 [ 0, %26 ], [ %39, %36 ]
  %42 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 3
  store i8 %29, i8* %42, align 4, !tbaa !14
  %43 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 2
  store i16 2, i16* %43, align 2, !tbaa !16
  %44 = getelementptr inbounds i8, i8* %20, i64 30
  %45 = bitcast i8* %44 to i32*
  %46 = load i32, i32* %45, align 4, !tbaa !17
  %47 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 0, i32 0, i64 0
  store i32 %46, i32* %47, align 4, !tbaa !18
  %48 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 1
  store i16 %41, i16* %48, align 4, !tbaa !19
  %49 = getelementptr inbounds i8, i8* %20, i64 16
  %50 = bitcast i8* %49 to i16*
  %51 = load i16, i16* %50, align 2, !tbaa !20
  %52 = tail call i16 @llvm.bswap.i16(i16 %51) #3
  %53 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %21) #3
  %54 = icmp eq i8* %53, null
  br i1 %54, label %144, label %55

; <label>:55:                                     ; preds = %40
  %56 = getelementptr inbounds i8, i8* %53, i64 32
  %57 = bitcast i8* %56 to i16*
  %58 = load i16, i16* %57, align 4, !tbaa !21
  %59 = icmp eq i16 %58, 2
  br i1 %59, label %60, label %144

; <label>:60:                                     ; preds = %55
  %61 = bitcast %struct.xdp_md* %0 to i8*
  %62 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %61, i32 -20) #3
  %63 = icmp eq i32 %62, 0
  br i1 %63, label %64, label %144

; <label>:64:                                     ; preds = %60
  %65 = load i32, i32* %9, align 4, !tbaa !7
  %66 = zext i32 %65 to i64
  %67 = inttoptr i64 %66 to i8*
  %68 = load i32, i32* %6, align 4, !tbaa !2
  %69 = zext i32 %68 to i64
  %70 = inttoptr i64 %66 to %struct.ethhdr*
  %71 = getelementptr i8, i8* %67, i64 14
  %72 = getelementptr i8, i8* %67, i64 20
  %73 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %70, i64 1
  %74 = inttoptr i64 %69 to %struct.ethhdr*
  %75 = icmp ugt %struct.ethhdr* %73, %74
  br i1 %75, label %144, label %76

; <label>:76:                                     ; preds = %64
  %77 = getelementptr inbounds i8, i8* %67, i64 34
  %78 = bitcast i8* %77 to %struct.ethhdr*
  %79 = icmp ugt %struct.ethhdr* %78, %74
  br i1 %79, label %144, label %80

; <label>:80:                                     ; preds = %76
  %81 = bitcast i8* %77 to %struct.iphdr*
  %82 = inttoptr i64 %69 to %struct.iphdr*
  %83 = icmp ugt %struct.iphdr* %81, %82
  br i1 %83, label %144, label %84

; <label>:84:                                     ; preds = %80
  %85 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %70, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %85, i8* %72, i64 6, i32 1, i1 false) #3
  %86 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %70, i64 0, i32 0, i64 0
  %87 = getelementptr inbounds i8, i8* %53, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %86, i8* nonnull %87, i64 6, i32 1, i1 false) #3
  %88 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %70, i64 0, i32 2
  store i16 8, i16* %88, align 1, !tbaa !8
  store i8 69, i8* %71, align 4
  %89 = bitcast i8* %72 to i16*
  store i16 0, i16* %89, align 2, !tbaa !23
  %90 = getelementptr inbounds i8, i8* %67, i64 23
  store i8 4, i8* %90, align 1, !tbaa !11
  %91 = getelementptr inbounds i8, i8* %67, i64 24
  %92 = bitcast i8* %91 to i16*
  store i16 0, i16* %92, align 2, !tbaa !24
  %93 = getelementptr inbounds i8, i8* %67, i64 15
  store i8 0, i8* %93, align 1, !tbaa !25
  %94 = add i16 %52, 20
  %95 = call i16 @llvm.bswap.i16(i16 %94) #3
  %96 = getelementptr inbounds i8, i8* %67, i64 16
  %97 = bitcast i8* %96 to i16*
  store i16 %95, i16* %97, align 2, !tbaa !20
  %98 = getelementptr inbounds i8, i8* %53, i64 16
  %99 = bitcast i8* %98 to i32*
  %100 = load i32, i32* %99, align 4, !tbaa !18
  %101 = getelementptr inbounds i8, i8* %67, i64 30
  %102 = bitcast i8* %101 to i32*
  store i32 %100, i32* %102, align 4, !tbaa !17
  %103 = bitcast i8* %53 to i32*
  %104 = load i32, i32* %103, align 4, !tbaa !18
  %105 = getelementptr inbounds i8, i8* %67, i64 26
  %106 = bitcast i8* %105 to i32*
  store i32 %104, i32* %106, align 4, !tbaa !26
  %107 = getelementptr inbounds i8, i8* %67, i64 22
  store i8 8, i8* %107, align 4, !tbaa !27
  %108 = bitcast i8* %71 to i16*
  %109 = load i16, i16* %108, align 2, !tbaa !13
  %110 = zext i16 %109 to i32
  %111 = getelementptr inbounds i8, i8* %67, i64 18
  %112 = bitcast i8* %111 to i16*
  %113 = zext i16 %95 to i32
  %114 = add nuw nsw i32 %110, %113
  %115 = load i16, i16* %112, align 2, !tbaa !13
  %116 = zext i16 %115 to i32
  %117 = add nuw nsw i32 %114, %116
  %118 = bitcast i8* %107 to i16*
  %119 = load i16, i16* %118, align 2, !tbaa !13
  %120 = zext i16 %119 to i32
  %121 = add nuw nsw i32 %117, %120
  %122 = and i32 %104, 65535
  %123 = add nuw nsw i32 %121, %122
  %124 = lshr i32 %104, 16
  %125 = add nuw nsw i32 %123, %124
  %126 = and i32 %100, 65535
  %127 = add nuw nsw i32 %125, %126
  %128 = lshr i32 %100, 16
  %129 = add i32 %127, %128
  %130 = lshr i32 %129, 16
  %131 = add i32 %130, %129
  %132 = trunc i32 %131 to i16
  %133 = xor i16 %132, -1
  store i16 %133, i16* %92, align 2, !tbaa !24
  %134 = load i8, i8* %42, align 4, !tbaa !14
  %135 = zext i8 %134 to i32
  %136 = bitcast i32* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %136) #3
  store i32 %135, i32* %4, align 4, !tbaa !28
  %137 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %136) #3
  %138 = bitcast i8* %137 to i64*
  %139 = icmp eq i8* %137, null
  br i1 %139, label %143, label %140

; <label>:140:                                    ; preds = %84
  %141 = load i64, i64* %138, align 8, !tbaa !29
  %142 = add i64 %141, 1
  store i64 %142, i64* %138, align 8, !tbaa !29
  br label %143

; <label>:143:                                    ; preds = %140, %84
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %136) #3
  br label %144

; <label>:144:                                    ; preds = %19, %30, %33, %40, %55, %60, %64, %76, %80, %143
  %145 = phi i32 [ 3, %143 ], [ 1, %19 ], [ 2, %55 ], [ 2, %40 ], [ 1, %60 ], [ 1, %80 ], [ 1, %76 ], [ 1, %64 ], [ 1, %30 ], [ 1, %33 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %21) #3
  br label %235

; <label>:146:                                    ; preds = %16
  %147 = inttoptr i64 %11 to i8*
  %148 = bitcast %struct.vip* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %148) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %148, i8 0, i64 24, i32 4, i1 false) #3
  %149 = getelementptr inbounds i8, i8* %147, i64 54
  %150 = bitcast i8* %149 to %struct.ipv6hdr*
  %151 = inttoptr i64 %8 to %struct.ipv6hdr*
  %152 = icmp ugt %struct.ipv6hdr* %150, %151
  br i1 %152, label %233, label %153

; <label>:153:                                    ; preds = %146
  %154 = inttoptr i64 %8 to i8*
  %155 = getelementptr inbounds i8, i8* %147, i64 20
  %156 = load i8, i8* %155, align 2, !tbaa !31
  switch i8 %156, label %167 [
    i8 6, label %157
    i8 17, label %160
  ]

; <label>:157:                                    ; preds = %153
  %158 = getelementptr inbounds i8, i8* %147, i64 74
  %159 = icmp ugt i8* %158, %154
  br i1 %159, label %233, label %163

; <label>:160:                                    ; preds = %153
  %161 = getelementptr inbounds i8, i8* %147, i64 62
  %162 = icmp ugt i8* %161, %154
  br i1 %162, label %233, label %163

; <label>:163:                                    ; preds = %160, %157
  %164 = getelementptr inbounds i8, i8* %147, i64 56
  %165 = bitcast i8* %164 to i16*
  %166 = load i16, i16* %165, align 2, !tbaa !13
  br label %167

; <label>:167:                                    ; preds = %163, %153
  %168 = phi i16 [ 0, %153 ], [ %166, %163 ]
  %169 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 3
  store i8 %156, i8* %169, align 4, !tbaa !14
  %170 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 2
  store i16 10, i16* %170, align 2, !tbaa !16
  %171 = getelementptr inbounds i8, i8* %147, i64 38
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %148, i8* nonnull %171, i64 16, i32 4, i1 false) #3
  %172 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 1
  store i16 %168, i16* %172, align 4, !tbaa !19
  %173 = getelementptr inbounds i8, i8* %147, i64 18
  %174 = bitcast i8* %173 to i16*
  %175 = load i16, i16* %174, align 4, !tbaa !34
  %176 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %148) #3
  %177 = icmp eq i8* %176, null
  br i1 %177, label %233, label %178

; <label>:178:                                    ; preds = %167
  %179 = getelementptr inbounds i8, i8* %176, i64 32
  %180 = bitcast i8* %179 to i16*
  %181 = load i16, i16* %180, align 4, !tbaa !21
  %182 = icmp eq i16 %181, 10
  br i1 %182, label %183, label %233

; <label>:183:                                    ; preds = %178
  %184 = bitcast %struct.xdp_md* %0 to i8*
  %185 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %184, i32 -40) #3
  %186 = icmp eq i32 %185, 0
  br i1 %186, label %187, label %233

; <label>:187:                                    ; preds = %183
  %188 = load i32, i32* %9, align 4, !tbaa !7
  %189 = zext i32 %188 to i64
  %190 = inttoptr i64 %189 to i8*
  %191 = load i32, i32* %6, align 4, !tbaa !2
  %192 = zext i32 %191 to i64
  %193 = inttoptr i64 %189 to %struct.ethhdr*
  %194 = getelementptr i8, i8* %190, i64 14
  %195 = getelementptr i8, i8* %190, i64 40
  %196 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %193, i64 1
  %197 = inttoptr i64 %192 to %struct.ethhdr*
  %198 = icmp ugt %struct.ethhdr* %196, %197
  br i1 %198, label %233, label %199

; <label>:199:                                    ; preds = %187
  %200 = getelementptr inbounds i8, i8* %190, i64 54
  %201 = bitcast i8* %200 to %struct.ethhdr*
  %202 = icmp ugt %struct.ethhdr* %201, %197
  br i1 %202, label %233, label %203

; <label>:203:                                    ; preds = %199
  %204 = bitcast i8* %200 to %struct.ipv6hdr*
  %205 = inttoptr i64 %192 to %struct.ipv6hdr*
  %206 = icmp ugt %struct.ipv6hdr* %204, %205
  br i1 %206, label %233, label %207

; <label>:207:                                    ; preds = %203
  %208 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %193, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %208, i8* %195, i64 6, i32 1, i1 false) #3
  %209 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %193, i64 0, i32 0, i64 0
  %210 = getelementptr inbounds i8, i8* %176, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %209, i8* nonnull %210, i64 6, i32 1, i1 false) #3
  %211 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %193, i64 0, i32 2
  store i16 -8826, i16* %211, align 1, !tbaa !8
  store i8 96, i8* %194, align 4
  %212 = getelementptr inbounds i8, i8* %190, i64 15
  call void @llvm.memset.p0i8.i64(i8* nonnull %212, i8 0, i64 3, i32 1, i1 false) #3
  %213 = call i16 @llvm.bswap.i16(i16 %175) #3
  %214 = add i16 %213, 40
  %215 = call i16 @llvm.bswap.i16(i16 %214) #3
  %216 = getelementptr inbounds i8, i8* %190, i64 18
  %217 = bitcast i8* %216 to i16*
  store i16 %215, i16* %217, align 4, !tbaa !34
  %218 = getelementptr inbounds i8, i8* %190, i64 20
  store i8 41, i8* %218, align 2, !tbaa !31
  %219 = getelementptr inbounds i8, i8* %190, i64 21
  store i8 8, i8* %219, align 1, !tbaa !35
  %220 = getelementptr inbounds i8, i8* %190, i64 22
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %220, i8* nonnull %176, i64 16, i32 4, i1 false) #3
  %221 = getelementptr inbounds i8, i8* %190, i64 38
  %222 = getelementptr inbounds i8, i8* %176, i64 16
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %221, i8* nonnull %222, i64 16, i32 4, i1 false) #3
  %223 = load i8, i8* %169, align 4, !tbaa !14
  %224 = zext i8 %223 to i32
  %225 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %225) #3
  store i32 %224, i32* %2, align 4, !tbaa !28
  %226 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %225) #3
  %227 = bitcast i8* %226 to i64*
  %228 = icmp eq i8* %226, null
  br i1 %228, label %232, label %229

; <label>:229:                                    ; preds = %207
  %230 = load i64, i64* %227, align 8, !tbaa !29
  %231 = add i64 %230, 1
  store i64 %231, i64* %227, align 8, !tbaa !29
  br label %232

; <label>:232:                                    ; preds = %229, %207
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %225) #3
  br label %233

; <label>:233:                                    ; preds = %146, %157, %160, %167, %178, %183, %187, %199, %203, %232
  %234 = phi i32 [ 3, %232 ], [ 1, %146 ], [ 2, %178 ], [ 2, %167 ], [ 1, %183 ], [ 1, %203 ], [ 1, %199 ], [ 1, %187 ], [ 1, %157 ], [ 1, %160 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %148) #3
  br label %235

; <label>:235:                                    ; preds = %16, %1, %233, %144
  %236 = phi i32 [ %145, %144 ], [ %234, %233 ], [ 1, %1 ], [ 2, %16 ]
  ret i32 %236
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
