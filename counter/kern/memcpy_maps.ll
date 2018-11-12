; ModuleID = 'kern/memcpy_maps.bc'
source_filename = "kern/memcpy_maps.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@m = global %struct.bpf_map_def { i32 2, i32 4, i32 4098, i32 2, i32 0, i32 0, i32 0 }, section "maps", align 4
@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268288, section "version", align 4
@llvm.used = appending global [4 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @memcpy_maps to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define i32 @memcpy_maps(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/memcpy-maps" {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %4) #2
  store i32 0, i32* %2, align 4, !tbaa !2
  %5 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %4) #2
  %6 = bitcast i32* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %6) #2
  store i32 1, i32* %3, align 4, !tbaa !2
  %7 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %6) #2
  %8 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 0
  %9 = load i32, i32* %8, align 4, !tbaa !6
  %10 = zext i32 %9 to i64
  %11 = icmp ne i8* %5, null
  %12 = icmp ne i8* %7, null
  %13 = and i1 %11, %12
  br i1 %13, label %14, label %60

; <label>:14:                                     ; preds = %1
  %15 = icmp eq i32 %9, 0
  br i1 %15, label %60, label %16

; <label>:16:                                     ; preds = %14
  %17 = add nsw i64 %10, -1
  %18 = and i64 %10, 3
  %19 = icmp ult i64 %17, 3
  br i1 %19, label %46, label %20

; <label>:20:                                     ; preds = %16
  %21 = sub nsw i64 %10, %18
  br label %22

; <label>:22:                                     ; preds = %22, %20
  %23 = phi i64 [ 0, %20 ], [ %43, %22 ]
  %24 = phi i64 [ %21, %20 ], [ %44, %22 ]
  %25 = and i64 %23, 4088
  %26 = getelementptr inbounds i8, i8* %7, i64 %25
  %27 = load i8, i8* %26, align 1, !tbaa !8
  %28 = getelementptr inbounds i8, i8* %5, i64 %25
  store i8 %27, i8* %28, align 1, !tbaa !8
  %29 = and i64 %23, 4088
  %30 = getelementptr inbounds i8, i8* %7, i64 %29
  %31 = load i8, i8* %30, align 1, !tbaa !8
  %32 = getelementptr inbounds i8, i8* %5, i64 %29
  store i8 %31, i8* %32, align 1, !tbaa !8
  %33 = and i64 %23, 4088
  %34 = or i64 %33, 2
  %35 = getelementptr inbounds i8, i8* %7, i64 %34
  %36 = load i8, i8* %35, align 1, !tbaa !8
  %37 = getelementptr inbounds i8, i8* %5, i64 %34
  store i8 %36, i8* %37, align 1, !tbaa !8
  %38 = and i64 %23, 4088
  %39 = or i64 %38, 2
  %40 = getelementptr inbounds i8, i8* %7, i64 %39
  %41 = load i8, i8* %40, align 1, !tbaa !8
  %42 = getelementptr inbounds i8, i8* %5, i64 %39
  store i8 %41, i8* %42, align 1, !tbaa !8
  %43 = add nuw nsw i64 %23, 4
  %44 = add i64 %24, -4
  %45 = icmp eq i64 %44, 0
  br i1 %45, label %46, label %22

; <label>:46:                                     ; preds = %22, %16
  %47 = phi i64 [ 0, %16 ], [ %43, %22 ]
  %48 = icmp eq i64 %18, 0
  br i1 %48, label %60, label %49

; <label>:49:                                     ; preds = %46
  br label %50

; <label>:50:                                     ; preds = %50, %49
  %51 = phi i64 [ %57, %50 ], [ %47, %49 ]
  %52 = phi i64 [ %58, %50 ], [ %18, %49 ]
  %53 = and i64 %51, 4090
  %54 = getelementptr inbounds i8, i8* %7, i64 %53
  %55 = load i8, i8* %54, align 1, !tbaa !8
  %56 = getelementptr inbounds i8, i8* %5, i64 %53
  store i8 %55, i8* %56, align 1, !tbaa !8
  %57 = add nuw nsw i64 %51, 1
  %58 = add i64 %52, -1
  %59 = icmp eq i64 %58, 0
  br i1 %59, label %60, label %50, !llvm.loop !9

; <label>:60:                                     ; preds = %46, %50, %14, %1
  %61 = phi i32 [ 1, %1 ], [ 0, %14 ], [ 0, %50 ], [ 0, %46 ]
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %6) #2
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %4) #2
  ret i32 %61
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!2 = !{!3, !3, i64 0}
!3 = !{!"int", !4, i64 0}
!4 = !{!"omnipotent char", !5, i64 0}
!5 = !{!"Simple C/C++ TBAA"}
!6 = !{!7, !3, i64 0}
!7 = !{!"__sk_buff", !3, i64 0, !3, i64 4, !3, i64 8, !3, i64 12, !3, i64 16, !3, i64 20, !3, i64 24, !3, i64 28, !3, i64 32, !3, i64 36, !3, i64 40, !3, i64 44, !4, i64 48, !3, i64 68, !3, i64 72, !3, i64 76, !3, i64 80, !3, i64 84, !3, i64 88, !3, i64 92, !3, i64 96, !4, i64 100, !4, i64 116, !3, i64 132, !3, i64 136, !3, i64 140}
!8 = !{!4, !4, i64 0}
!9 = distinct !{!9, !10}
!10 = !{!"llvm.loop.unroll.disable"}
