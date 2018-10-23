; ModuleID = 'kern/manual_memset.bc'
source_filename = "kern/manual_memset.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268544, section "version", align 4
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @manual_memset to i8*)], section "llvm.metadata"

; Function Attrs: norecurse nounwind uwtable
define i32 @manual_memset(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/manual-memset" {
  %2 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %3 = load i32, i32* %2, align 4, !tbaa !2
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i8*
  %6 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %7 = load i32, i32* %6, align 4, !tbaa !7
  %8 = zext i32 %7 to i64
  %9 = inttoptr i64 %8 to i8*
  %10 = getelementptr inbounds i8, i8* %5, i64 -1
  %11 = icmp ult i8* %10, %9
  br i1 %11, label %17, label %12

; <label>:12:                                     ; preds = %1
  br label %13

; <label>:13:                                     ; preds = %12, %13
  %14 = phi i8* [ %15, %13 ], [ %10, %12 ]
  store i8 15, i8* %14, align 1, !tbaa !8
  %15 = getelementptr inbounds i8, i8* %14, i64 -1
  %16 = icmp ult i8* %15, %9
  br i1 %16, label %17, label %13

; <label>:17:                                     ; preds = %13, %1
  ret i32 0
}

attributes #0 = { norecurse nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!2 = !{!3, !4, i64 80}
!3 = !{!"__sk_buff", !4, i64 0, !4, i64 4, !4, i64 8, !4, i64 12, !4, i64 16, !4, i64 20, !4, i64 24, !4, i64 28, !4, i64 32, !4, i64 36, !4, i64 40, !4, i64 44, !5, i64 48, !4, i64 68, !4, i64 72, !4, i64 76, !4, i64 80, !4, i64 84, !4, i64 88, !4, i64 92, !4, i64 96, !5, i64 100, !5, i64 116, !4, i64 132, !4, i64 136, !4, i64 140}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = !{!3, !4, i64 76}
!8 = !{!5, !5, i64 0}
