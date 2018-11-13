; ModuleID = 'kern/memcpy_maps_fails_verification.bc'
source_filename = "kern/memcpy_maps_fails_verification.c"
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
  %4 = alloca i64, align 8
  %5 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %5) #2
  store i32 0, i32* %2, align 4, !tbaa !2
  %6 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %5) #2
  %7 = bitcast i32* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %7) #2
  store i32 1, i32* %3, align 4, !tbaa !2
  %8 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %7) #2
  %9 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 0
  %10 = load i32, i32* %9, align 4, !tbaa !6
  %11 = zext i32 %10 to i64
  %12 = icmp ne i8* %6, null
  %13 = icmp ne i8* %8, null
  %14 = and i1 %12, %13
  br i1 %14, label %15, label %48

; <label>:15:                                     ; preds = %1
  %16 = bitcast i64* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %16)
  store volatile i64 1, i64* %4, align 8
  %17 = icmp eq i32 %10, 0
  br i1 %17, label %32, label %18

; <label>:18:                                     ; preds = %15
  %19 = and i64 %11, 1
  %20 = icmp eq i32 %10, 1
  br i1 %20, label %25, label %21

; <label>:21:                                     ; preds = %18
  %22 = sub nsw i64 %11, %19
  br label %33

; <label>:23:                                     ; preds = %33
  %24 = urem i64 %45, 4090
  br label %25

; <label>:25:                                     ; preds = %23, %18
  %26 = phi i64 [ 0, %18 ], [ %24, %23 ]
  %27 = icmp eq i64 %19, 0
  br i1 %27, label %32, label %28

; <label>:28:                                     ; preds = %25
  %29 = getelementptr inbounds i8, i8* %8, i64 %26
  %30 = load i8, i8* %29, align 1, !tbaa !8
  %31 = getelementptr inbounds i8, i8* %6, i64 %26
  store i8 %30, i8* %31, align 1, !tbaa !8
  br label %32

; <label>:32:                                     ; preds = %28, %25, %15
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %16)
  br label %48

; <label>:33:                                     ; preds = %33, %21
  %34 = phi i64 [ 0, %21 ], [ %45, %33 ]
  %35 = phi i64 [ %22, %21 ], [ %46, %33 ]
  %36 = urem i64 %34, 4090
  %37 = getelementptr inbounds i8, i8* %8, i64 %36
  %38 = load i8, i8* %37, align 1, !tbaa !8
  %39 = getelementptr inbounds i8, i8* %6, i64 %36
  store i8 %38, i8* %39, align 1, !tbaa !8
  %40 = or i64 %34, 1
  %41 = urem i64 %40, 4090
  %42 = getelementptr inbounds i8, i8* %8, i64 %41
  %43 = load i8, i8* %42, align 1, !tbaa !8
  %44 = getelementptr inbounds i8, i8* %6, i64 %41
  store i8 %43, i8* %44, align 1, !tbaa !8
  %45 = add nuw nsw i64 %34, 2
  %46 = add i64 %35, -2
  %47 = icmp eq i64 %46, 0
  br i1 %47, label %23, label %33

; <label>:48:                                     ; preds = %1, %32
  %49 = phi i32 [ 0, %32 ], [ 1, %1 ]
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %7) #2
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %5) #2
  ret i32 %49
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
