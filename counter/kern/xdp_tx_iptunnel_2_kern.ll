; ModuleID = 'kern/xdp_tx_iptunnel_2_kern.bc'
source_filename = "kern/xdp_tx_iptunnel_2_kern.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.vip = type { %union.anon.1, i16, i16, i8 }
%union.anon.1 = type { [4 x i32] }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

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
  %9 = inttoptr i64 %8 to i8*
  %10 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0
  %11 = load i32, i32* %10, align 4, !tbaa !7
  %12 = zext i32 %11 to i64
  %13 = inttoptr i64 %12 to i8*
  %14 = inttoptr i64 %12 to %struct.ethhdr*
  %15 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %14, i64 1
  %16 = inttoptr i64 %8 to %struct.ethhdr*
  %17 = icmp ugt %struct.ethhdr* %15, %16
  br i1 %17, label %188, label %18

; <label>:18:                                     ; preds = %1
  %19 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %14, i64 0, i32 2
  %20 = load i16, i16* %19, align 1, !tbaa !8
  switch i16 %20, label %188 [
    i16 8, label %21
    i16 -8826, label %123
  ]

; <label>:21:                                     ; preds = %18
  %22 = getelementptr i8, i8* %13, i64 14
  %23 = bitcast %struct.vip* %5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %23) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %23, i8 0, i64 24, i32 4, i1 false) #3
  %24 = getelementptr inbounds i8, i8* %13, i64 34
  %25 = icmp ugt i8* %24, %9
  br i1 %25, label %121, label %26

; <label>:26:                                     ; preds = %21
  %27 = getelementptr inbounds i8, i8* %13, i64 23
  %28 = load i8, i8* %27, align 1, !tbaa !11
  switch i8 %28, label %39 [
    i8 6, label %29
    i8 17, label %32
  ]

; <label>:29:                                     ; preds = %26
  %30 = getelementptr inbounds i8, i8* %13, i64 54
  %31 = icmp ugt i8* %30, %9
  br i1 %31, label %121, label %35

; <label>:32:                                     ; preds = %26
  %33 = getelementptr inbounds i8, i8* %13, i64 42
  %34 = icmp ugt i8* %33, %9
  br i1 %34, label %121, label %35

; <label>:35:                                     ; preds = %32, %29
  %36 = getelementptr inbounds i8, i8* %13, i64 36
  %37 = bitcast i8* %36 to i16*
  %38 = load i16, i16* %37, align 2, !tbaa !13
  br label %39

; <label>:39:                                     ; preds = %35, %26
  %40 = phi i16 [ 0, %26 ], [ %38, %35 ]
  %41 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 3
  store i8 %28, i8* %41, align 4, !tbaa !14
  %42 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 2
  store i16 2, i16* %42, align 2, !tbaa !16
  %43 = getelementptr inbounds i8, i8* %13, i64 30
  %44 = bitcast i8* %43 to i32*
  %45 = load i32, i32* %44, align 4, !tbaa !17
  %46 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 0, i32 0, i64 0
  store i32 %45, i32* %46, align 4, !tbaa !18
  %47 = getelementptr inbounds %struct.vip, %struct.vip* %5, i64 0, i32 1
  store i16 %40, i16* %47, align 4, !tbaa !19
  %48 = getelementptr inbounds i8, i8* %13, i64 16
  %49 = bitcast i8* %48 to i16*
  %50 = load i16, i16* %49, align 2, !tbaa !20
  %51 = tail call i16 @llvm.bswap.i16(i16 %50) #3
  %52 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %23) #3
  %53 = icmp eq i8* %52, null
  br i1 %53, label %121, label %54

; <label>:54:                                     ; preds = %39
  %55 = getelementptr inbounds i8, i8* %52, i64 32
  %56 = bitcast i8* %55 to i16*
  %57 = load i16, i16* %56, align 4, !tbaa !21
  %58 = icmp eq i16 %57, 2
  br i1 %58, label %59, label %121

; <label>:59:                                     ; preds = %54
  %60 = bitcast %struct.xdp_md* %0 to i8*
  %61 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %60, i32 -20) #3
  %62 = icmp eq i32 %61, 0
  br i1 %62, label %63, label %121

; <label>:63:                                     ; preds = %59
  %64 = getelementptr i8, i8* %13, i64 20
  %65 = icmp ugt i8* %22, %9
  br i1 %65, label %121, label %66

; <label>:66:                                     ; preds = %63
  %67 = getelementptr inbounds i8, i8* %13, i64 6
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %67, i8* %64, i64 6, i32 1, i1 false) #3
  %68 = getelementptr inbounds i8, i8* %52, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %13, i8* nonnull %68, i64 6, i32 1, i1 false) #3
  %69 = getelementptr inbounds i8, i8* %13, i64 12
  %70 = bitcast i8* %69 to i16*
  store i16 8, i16* %70, align 1, !tbaa !8
  store i8 69, i8* %22, align 4
  %71 = bitcast i8* %64 to i16*
  store i16 0, i16* %71, align 2, !tbaa !23
  store i8 4, i8* %27, align 1, !tbaa !11
  %72 = getelementptr inbounds i8, i8* %13, i64 24
  %73 = bitcast i8* %72 to i16*
  store i16 0, i16* %73, align 2, !tbaa !24
  %74 = getelementptr inbounds i8, i8* %13, i64 15
  store i8 0, i8* %74, align 1, !tbaa !25
  %75 = add i16 %51, 20
  %76 = call i16 @llvm.bswap.i16(i16 %75) #3
  store i16 %76, i16* %49, align 2, !tbaa !20
  %77 = getelementptr inbounds i8, i8* %52, i64 16
  %78 = bitcast i8* %77 to i32*
  %79 = load i32, i32* %78, align 4, !tbaa !18
  store i32 %79, i32* %44, align 4, !tbaa !17
  %80 = bitcast i8* %52 to i32*
  %81 = load i32, i32* %80, align 4, !tbaa !18
  %82 = getelementptr inbounds i8, i8* %13, i64 26
  %83 = bitcast i8* %82 to i32*
  store i32 %81, i32* %83, align 4, !tbaa !26
  %84 = getelementptr inbounds i8, i8* %13, i64 22
  store i8 8, i8* %84, align 4, !tbaa !27
  %85 = bitcast i8* %22 to i16*
  %86 = load i16, i16* %85, align 2, !tbaa !13
  %87 = zext i16 %86 to i32
  %88 = getelementptr inbounds i8, i8* %13, i64 18
  %89 = bitcast i8* %88 to i16*
  %90 = zext i16 %76 to i32
  %91 = add nuw nsw i32 %87, %90
  %92 = load i16, i16* %89, align 2, !tbaa !13
  %93 = zext i16 %92 to i32
  %94 = add nuw nsw i32 %91, %93
  %95 = bitcast i8* %84 to i16*
  %96 = load i16, i16* %95, align 2, !tbaa !13
  %97 = zext i16 %96 to i32
  %98 = add nuw nsw i32 %94, %97
  %99 = and i32 %81, 65535
  %100 = add nuw nsw i32 %98, %99
  %101 = lshr i32 %81, 16
  %102 = add nuw nsw i32 %100, %101
  %103 = and i32 %79, 65535
  %104 = add nuw nsw i32 %102, %103
  %105 = lshr i32 %79, 16
  %106 = add i32 %104, %105
  %107 = lshr i32 %106, 16
  %108 = add i32 %107, %106
  %109 = trunc i32 %108 to i16
  %110 = xor i16 %109, -1
  store i16 %110, i16* %73, align 2, !tbaa !24
  %111 = load i8, i8* %41, align 4, !tbaa !14
  %112 = zext i8 %111 to i32
  %113 = bitcast i32* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %113) #3
  store i32 %112, i32* %4, align 4, !tbaa !28
  %114 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %113) #3
  %115 = bitcast i8* %114 to i64*
  %116 = icmp eq i8* %114, null
  br i1 %116, label %120, label %117

; <label>:117:                                    ; preds = %66
  %118 = load i64, i64* %115, align 8, !tbaa !29
  %119 = add i64 %118, 1
  store i64 %119, i64* %115, align 8, !tbaa !29
  br label %120

; <label>:120:                                    ; preds = %117, %66
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %113) #3
  br label %121

; <label>:121:                                    ; preds = %21, %29, %32, %39, %54, %59, %63, %120
  %122 = phi i32 [ 3, %120 ], [ 1, %21 ], [ 2, %54 ], [ 2, %39 ], [ 1, %59 ], [ 1, %63 ], [ 1, %29 ], [ 1, %32 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %23) #3
  br label %188

; <label>:123:                                    ; preds = %18
  %124 = getelementptr i8, i8* %13, i64 14
  %125 = bitcast %struct.vip* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 24, i8* nonnull %125) #3
  call void @llvm.memset.p0i8.i64(i8* nonnull %125, i8 0, i64 24, i32 4, i1 false) #3
  %126 = getelementptr inbounds i8, i8* %13, i64 54
  %127 = icmp ugt i8* %126, %9
  br i1 %127, label %186, label %128

; <label>:128:                                    ; preds = %123
  %129 = getelementptr inbounds i8, i8* %13, i64 20
  %130 = load i8, i8* %129, align 2, !tbaa !31
  switch i8 %130, label %141 [
    i8 6, label %131
    i8 17, label %134
  ]

; <label>:131:                                    ; preds = %128
  %132 = getelementptr inbounds i8, i8* %13, i64 74
  %133 = icmp ugt i8* %132, %9
  br i1 %133, label %186, label %137

; <label>:134:                                    ; preds = %128
  %135 = getelementptr inbounds i8, i8* %13, i64 62
  %136 = icmp ugt i8* %135, %9
  br i1 %136, label %186, label %137

; <label>:137:                                    ; preds = %134, %131
  %138 = getelementptr inbounds i8, i8* %13, i64 56
  %139 = bitcast i8* %138 to i16*
  %140 = load i16, i16* %139, align 2, !tbaa !13
  br label %141

; <label>:141:                                    ; preds = %137, %128
  %142 = phi i16 [ 0, %128 ], [ %140, %137 ]
  %143 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 3
  store i8 %130, i8* %143, align 4, !tbaa !14
  %144 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 2
  store i16 10, i16* %144, align 2, !tbaa !16
  %145 = getelementptr inbounds i8, i8* %13, i64 38
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %125, i8* nonnull %145, i64 16, i32 4, i1 false) #3
  %146 = getelementptr inbounds %struct.vip, %struct.vip* %3, i64 0, i32 1
  store i16 %142, i16* %146, align 4, !tbaa !19
  %147 = getelementptr inbounds i8, i8* %13, i64 18
  %148 = bitcast i8* %147 to i16*
  %149 = load i16, i16* %148, align 4, !tbaa !34
  %150 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @vip2tnl to i8*), i8* nonnull %125) #3
  %151 = icmp eq i8* %150, null
  br i1 %151, label %186, label %152

; <label>:152:                                    ; preds = %141
  %153 = getelementptr inbounds i8, i8* %150, i64 32
  %154 = bitcast i8* %153 to i16*
  %155 = load i16, i16* %154, align 4, !tbaa !21
  %156 = icmp eq i16 %155, 10
  br i1 %156, label %157, label %186

; <label>:157:                                    ; preds = %152
  %158 = bitcast %struct.xdp_md* %0 to i8*
  %159 = call i32 inttoptr (i64 44 to i32 (i8*, i32)*)(i8* %158, i32 -40) #3
  %160 = icmp ne i32 %159, 0
  %161 = icmp ugt i8* %124, %9
  %162 = or i1 %161, %160
  br i1 %162, label %186, label %163

; <label>:163:                                    ; preds = %157
  %164 = getelementptr i8, i8* %13, i64 40
  %165 = getelementptr inbounds i8, i8* %13, i64 6
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %165, i8* %164, i64 6, i32 1, i1 false) #3
  %166 = getelementptr inbounds i8, i8* %150, i64 34
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %13, i8* nonnull %166, i64 6, i32 1, i1 false) #3
  %167 = getelementptr inbounds i8, i8* %13, i64 12
  %168 = bitcast i8* %167 to i16*
  store i16 -8826, i16* %168, align 1, !tbaa !8
  store i8 96, i8* %124, align 4
  %169 = getelementptr inbounds i8, i8* %13, i64 15
  call void @llvm.memset.p0i8.i64(i8* nonnull %169, i8 0, i64 3, i32 1, i1 false) #3
  %170 = call i16 @llvm.bswap.i16(i16 %149) #3
  %171 = add i16 %170, 40
  %172 = call i16 @llvm.bswap.i16(i16 %171) #3
  store i16 %172, i16* %148, align 4, !tbaa !34
  store i8 41, i8* %129, align 2, !tbaa !31
  %173 = getelementptr inbounds i8, i8* %13, i64 21
  store i8 8, i8* %173, align 1, !tbaa !35
  %174 = getelementptr inbounds i8, i8* %13, i64 22
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %174, i8* nonnull %150, i64 16, i32 4, i1 false) #3
  %175 = getelementptr inbounds i8, i8* %150, i64 16
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %145, i8* nonnull %175, i64 16, i32 4, i1 false) #3
  %176 = load i8, i8* %143, align 4, !tbaa !14
  %177 = zext i8 %176 to i32
  %178 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %178) #3
  store i32 %177, i32* %2, align 4, !tbaa !28
  %179 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %178) #3
  %180 = bitcast i8* %179 to i64*
  %181 = icmp eq i8* %179, null
  br i1 %181, label %185, label %182

; <label>:182:                                    ; preds = %163
  %183 = load i64, i64* %180, align 8, !tbaa !29
  %184 = add i64 %183, 1
  store i64 %184, i64* %180, align 8, !tbaa !29
  br label %185

; <label>:185:                                    ; preds = %182, %163
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %178) #3
  br label %186

; <label>:186:                                    ; preds = %123, %131, %134, %141, %152, %157, %185
  %187 = phi i32 [ 3, %185 ], [ 1, %123 ], [ 2, %152 ], [ 2, %141 ], [ 1, %157 ], [ 1, %131 ], [ 1, %134 ]
  call void @llvm.lifetime.end.p0i8(i64 24, i8* nonnull %125) #3
  br label %188

; <label>:188:                                    ; preds = %18, %1, %186, %121
  %189 = phi i32 [ %122, %121 ], [ %187, %186 ], [ 1, %1 ], [ 2, %18 ]
  ret i32 %189
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
