; ModuleID = 'kern/simple_loop_ptr.bc'
source_filename = "kern/simple_loop_ptr.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268288, section "version", align 4
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @prog to i8*)], section "llvm.metadata"

; Function Attrs: norecurse nounwind uwtable
define i32 @prog(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/loop-ptr" {
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %3 = load i32, i32* %2, align 4, !tbaa !2
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i64*
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %7 = load i32, i32* %6, align 4, !tbaa !7
  %8 = zext i32 %7 to i64
  %9 = inttoptr i64 %8 to i64*
  %10 = icmp ult i64* %5, %9
  br i1 %10, label %11, label %42

; <label>:11:                                     ; preds = %1
  %12 = inttoptr i64 %8 to i8*
  %13 = xor i64 %4, -1
  %14 = getelementptr i8, i8* %12, i64 %13
  %15 = ptrtoint i8* %14 to i64
  %16 = lshr i64 %15, 3
  %17 = add nuw nsw i64 %16, 1
  %18 = and i64 %17, 7
  %19 = icmp eq i64 %18, 0
  br i1 %19, label %27, label %20

; <label>:20:                                     ; preds = %11
  br label %21

; <label>:21:                                     ; preds = %21, %20
  %22 = phi i64* [ %24, %21 ], [ %5, %20 ]
  %23 = phi i64 [ %25, %21 ], [ %18, %20 ]
  store volatile i64 15, i64* %22, align 8, !tbaa !8
  %24 = getelementptr inbounds i64, i64* %22, i64 1
  %25 = add i64 %23, -1
  %26 = icmp eq i64 %25, 0
  br i1 %26, label %27, label %21, !llvm.loop !10

; <label>:27:                                     ; preds = %21, %11
  %28 = phi i64* [ %5, %11 ], [ %24, %21 ]
  %29 = icmp ult i8* %14, inttoptr (i64 56 to i8*)
  br i1 %29, label %42, label %30

; <label>:30:                                     ; preds = %27
  br label %31

; <label>:31:                                     ; preds = %31, %30
  %32 = phi i64* [ %28, %30 ], [ %40, %31 ]
  store volatile i64 15, i64* %32, align 8, !tbaa !8
  %33 = getelementptr inbounds i64, i64* %32, i64 1
  store volatile i64 15, i64* %33, align 8, !tbaa !8
  %34 = getelementptr inbounds i64, i64* %32, i64 2
  store volatile i64 15, i64* %34, align 8, !tbaa !8
  %35 = getelementptr inbounds i64, i64* %32, i64 3
  store volatile i64 15, i64* %35, align 8, !tbaa !8
  %36 = getelementptr inbounds i64, i64* %32, i64 4
  store volatile i64 15, i64* %36, align 8, !tbaa !8
  %37 = getelementptr inbounds i64, i64* %32, i64 5
  store volatile i64 15, i64* %37, align 8, !tbaa !8
  %38 = getelementptr inbounds i64, i64* %32, i64 6
  store volatile i64 15, i64* %38, align 8, !tbaa !8
  %39 = getelementptr inbounds i64, i64* %32, i64 7
  store volatile i64 15, i64* %39, align 8, !tbaa !8
  %40 = getelementptr inbounds i64, i64* %32, i64 8
  %41 = icmp ult i64* %40, %9
  br i1 %41, label %31, label %42

; <label>:42:                                     ; preds = %27, %31, %1
  ret i32 0
}

attributes #0 = { norecurse nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!2 = !{!3, !4, i64 76}
!3 = !{!"__sk_buff", !4, i64 0, !4, i64 4, !4, i64 8, !4, i64 12, !4, i64 16, !4, i64 20, !4, i64 24, !4, i64 28, !4, i64 32, !4, i64 36, !4, i64 40, !4, i64 44, !5, i64 48, !4, i64 68, !4, i64 72, !4, i64 76, !4, i64 80, !4, i64 84, !4, i64 88, !4, i64 92, !4, i64 96, !5, i64 100, !5, i64 116, !4, i64 132, !4, i64 136, !4, i64 140}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = !{!3, !4, i64 80}
!8 = !{!9, !9, i64 0}
!9 = !{!"long", !5, i64 0}
!10 = distinct !{!10, !11}
!11 = !{!"llvm.loop.unroll.disable"}
