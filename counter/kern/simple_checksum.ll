; ModuleID = 'kern/simple_checksum.bc'
source_filename = "kern/simple_checksum.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@m = global %struct.bpf_map_def { i32 2, i32 4, i32 1, i32 1, i32 0, i32 0, i32 0 }, section "maps", align 4
@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268288, section "version", align 4
@llvm.used = appending global [4 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @prog to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define i32 @prog(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/checksum" {
  %2 = alloca i32, align 4
  %3 = alloca i64, align 8
  %4 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %4) #2
  store i32 1, i32* %2, align 4, !tbaa !2
  %5 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %4) #2
  %6 = icmp eq i8* %5, null
  br i1 %6, label %37, label %7

; <label>:7:                                      ; preds = %1
  %8 = load i8, i8* %5, align 1, !tbaa !6
  %9 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %10 = load i32, i32* %9, align 4, !tbaa !7
  %11 = zext i32 %10 to i64
  %12 = inttoptr i64 %11 to i8*
  %13 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %14 = load i32, i32* %13, align 4, !tbaa !9
  %15 = zext i32 %14 to i64
  %16 = inttoptr i64 %15 to i8*
  %17 = bitcast i64* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %17)
  store volatile i64 1, i64* %3, align 8
  %18 = getelementptr inbounds i8, i8* %12, i64 8
  %19 = icmp ult i8* %18, %16
  br i1 %19, label %20, label %32

; <label>:20:                                     ; preds = %7
  br label %21

; <label>:21:                                     ; preds = %20, %21
  %22 = phi i32 [ %29, %21 ], [ 0, %20 ]
  %23 = phi i8* [ %28, %21 ], [ %12, %20 ]
  %24 = load i8, i8* %23, align 1, !tbaa !6
  %25 = zext i8 %24 to i32
  %26 = add nuw nsw i32 %22, %25
  %27 = load volatile i64, i64* %3, align 8
  %28 = getelementptr inbounds i8, i8* %23, i64 %27
  %29 = and i32 %26, 255
  %30 = getelementptr inbounds i8, i8* %28, i64 8
  %31 = icmp ult i8* %30, %16
  br i1 %31, label %21, label %32

; <label>:32:                                     ; preds = %21, %7
  %33 = phi i32 [ 0, %7 ], [ %29, %21 ]
  %34 = zext i8 %8 to i32
  %35 = icmp ne i32 %33, %34
  %36 = zext i1 %35 to i32
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %17)
  br label %37

; <label>:37:                                     ; preds = %1, %32
  %38 = phi i32 [ %36, %32 ], [ 1, %1 ]
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %4) #2
  ret i32 %38
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
!6 = !{!4, !4, i64 0}
!7 = !{!8, !3, i64 76}
!8 = !{!"__sk_buff", !3, i64 0, !3, i64 4, !3, i64 8, !3, i64 12, !3, i64 16, !3, i64 20, !3, i64 24, !3, i64 28, !3, i64 32, !3, i64 36, !3, i64 40, !3, i64 44, !4, i64 48, !3, i64 68, !3, i64 72, !3, i64 76, !3, i64 80, !3, i64 84, !3, i64 88, !3, i64 92, !3, i64 96, !4, i64 100, !4, i64 116, !3, i64 132, !3, i64 136, !3, i64 140}
!9 = !{!8, !3, i64 80}
