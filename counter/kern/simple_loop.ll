; ModuleID = 'kern/simple_loop.bc'
source_filename = "kern/simple_loop.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268288, section "version", align 4
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @prog to i8*)], section "llvm.metadata"

; Function Attrs: norecurse nounwind uwtable
define i32 @prog(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/loop" {
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %3 = load i32, i32* %2, align 4, !tbaa !2
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i8*
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %7 = load i32, i32* %6, align 4, !tbaa !7
  %8 = zext i32 %7 to i64
  %9 = sub nsw i64 %8, %4
  %10 = icmp sgt i64 %9, 0
  br i1 %10, label %11, label %92

; <label>:11:                                     ; preds = %1
  %12 = add nsw i64 %4, -1
  %13 = sub nsw i64 %12, %8
  %14 = icmp sgt i64 %13, -2
  %15 = select i1 %14, i64 %13, i64 -2
  %16 = add nsw i64 %15, %8
  %17 = add nsw i64 %16, 2
  %18 = sub nsw i64 %17, %4
  %19 = icmp ult i64 %18, 8
  br i1 %19, label %84, label %20

; <label>:20:                                     ; preds = %11
  %21 = and i64 %18, -8
  %22 = sub i64 %9, %21
  %23 = insertelement <4 x i64> undef, i64 %9, i32 0
  %24 = shufflevector <4 x i64> %23, <4 x i64> undef, <4 x i32> zeroinitializer
  %25 = add <4 x i64> %24, <i64 0, i64 -1, i64 -2, i64 -3>
  %26 = add i64 %21, -8
  %27 = lshr exact i64 %26, 3
  %28 = add nuw nsw i64 %27, 1
  %29 = and i64 %28, 1
  %30 = icmp eq i64 %26, 0
  br i1 %30, label %65, label %31

; <label>:31:                                     ; preds = %20
  %32 = sub nsw i64 %28, %29
  br label %33

; <label>:33:                                     ; preds = %33, %31
  %34 = phi <4 x i64> [ %25, %31 ], [ %62, %33 ]
  %35 = phi i64 [ %32, %31 ], [ %63, %33 ]
  %36 = add nsw <4 x i64> %34, <i64 -1, i64 -1, i64 -1, i64 -1>
  %37 = trunc <4 x i64> %36 to <4 x i8>
  %38 = trunc <4 x i64> %34 to <4 x i8>
  %39 = add <4 x i8> %38, <i8 -5, i8 -5, i8 -5, i8 -5>
  %40 = extractelement <4 x i64> %36, i32 0
  %41 = getelementptr inbounds i8, i8* %5, i64 %40
  %42 = shufflevector <4 x i8> %37, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %43 = getelementptr i8, i8* %41, i64 -3
  %44 = bitcast i8* %43 to <4 x i8>*
  store <4 x i8> %42, <4 x i8>* %44, align 1, !tbaa !8
  %45 = shufflevector <4 x i8> %39, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %46 = getelementptr i8, i8* %41, i64 -4
  %47 = getelementptr i8, i8* %46, i64 -3
  %48 = bitcast i8* %47 to <4 x i8>*
  store <4 x i8> %45, <4 x i8>* %48, align 1, !tbaa !8
  %49 = add <4 x i64> %34, <i64 -9, i64 -9, i64 -9, i64 -9>
  %50 = trunc <4 x i64> %49 to <4 x i8>
  %51 = trunc <4 x i64> %34 to <4 x i8>
  %52 = add <4 x i8> %51, <i8 -13, i8 -13, i8 -13, i8 -13>
  %53 = extractelement <4 x i64> %49, i32 0
  %54 = getelementptr inbounds i8, i8* %5, i64 %53
  %55 = shufflevector <4 x i8> %50, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %56 = getelementptr i8, i8* %54, i64 -3
  %57 = bitcast i8* %56 to <4 x i8>*
  store <4 x i8> %55, <4 x i8>* %57, align 1, !tbaa !8
  %58 = shufflevector <4 x i8> %52, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %59 = getelementptr i8, i8* %54, i64 -4
  %60 = getelementptr i8, i8* %59, i64 -3
  %61 = bitcast i8* %60 to <4 x i8>*
  store <4 x i8> %58, <4 x i8>* %61, align 1, !tbaa !8
  %62 = add <4 x i64> %34, <i64 -16, i64 -16, i64 -16, i64 -16>
  %63 = add i64 %35, -2
  %64 = icmp eq i64 %63, 0
  br i1 %64, label %65, label %33, !llvm.loop !9

; <label>:65:                                     ; preds = %33, %20
  %66 = phi <4 x i64> [ %25, %20 ], [ %62, %33 ]
  %67 = icmp eq i64 %29, 0
  br i1 %67, label %82, label %68

; <label>:68:                                     ; preds = %65
  %69 = add nsw <4 x i64> %66, <i64 -1, i64 -1, i64 -1, i64 -1>
  %70 = trunc <4 x i64> %69 to <4 x i8>
  %71 = trunc <4 x i64> %66 to <4 x i8>
  %72 = add <4 x i8> %71, <i8 -5, i8 -5, i8 -5, i8 -5>
  %73 = extractelement <4 x i64> %69, i32 0
  %74 = getelementptr inbounds i8, i8* %5, i64 %73
  %75 = shufflevector <4 x i8> %70, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %76 = getelementptr i8, i8* %74, i64 -3
  %77 = bitcast i8* %76 to <4 x i8>*
  store <4 x i8> %75, <4 x i8>* %77, align 1, !tbaa !8
  %78 = shufflevector <4 x i8> %72, <4 x i8> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  %79 = getelementptr i8, i8* %74, i64 -4
  %80 = getelementptr i8, i8* %79, i64 -3
  %81 = bitcast i8* %80 to <4 x i8>*
  store <4 x i8> %78, <4 x i8>* %81, align 1, !tbaa !8
  br label %82

; <label>:82:                                     ; preds = %65, %68
  %83 = icmp eq i64 %18, %21
  br i1 %83, label %92, label %84

; <label>:84:                                     ; preds = %82, %11
  %85 = phi i64 [ %9, %11 ], [ %22, %82 ]
  br label %86

; <label>:86:                                     ; preds = %84, %86
  %87 = phi i64 [ %88, %86 ], [ %85, %84 ]
  %88 = add nsw i64 %87, -1
  %89 = trunc i64 %88 to i8
  %90 = getelementptr inbounds i8, i8* %5, i64 %88
  store i8 %89, i8* %90, align 1, !tbaa !8
  %91 = icmp sgt i64 %87, 1
  br i1 %91, label %86, label %92, !llvm.loop !11

; <label>:92:                                     ; preds = %86, %82, %1
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
!8 = !{!5, !5, i64 0}
!9 = distinct !{!9, !10}
!10 = !{!"llvm.loop.isvectorized", i32 1}
!11 = distinct !{!11, !12, !10}
!12 = !{!"llvm.loop.unroll.runtime.disable"}
