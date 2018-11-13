; ModuleID = 'kern/manual_memset_forward.bc'
source_filename = "kern/manual_memset_forward.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32 }

@_license = global [4 x i8] c"GPL\00", section "license", align 1
@_version = global i32 268544, section "version", align 4
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32* @_version to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @manual_memset to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define i32 @manual_memset(%struct.__sk_buff* nocapture readonly) #0 section "sk_skb/manual-memset" {
  %2 = alloca i64, align 8
  %3 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %4 = load i32, i32* %3, align 4, !tbaa !2
  %5 = zext i32 %4 to i64
  %6 = inttoptr i64 %5 to i64*
  %7 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %8 = load i32, i32* %7, align 4, !tbaa !7
  %9 = zext i32 %8 to i64
  %10 = inttoptr i64 %9 to i64*
  %11 = bitcast i64* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %11)
  store volatile i64 1, i64* %2, align 8
  %12 = getelementptr inbounds i64, i64* %10, i64 8
  %13 = icmp ugt i64* %12, %6
  br i1 %13, label %21, label %14

; <label>:14:                                     ; preds = %1
  br label %15

; <label>:15:                                     ; preds = %14, %15
  %16 = phi i64* [ %18, %15 ], [ %10, %14 ]
  store i64 4294967295, i64* %16, align 8, !tbaa !8
  %17 = load volatile i64, i64* %2, align 8
  %18 = getelementptr inbounds i64, i64* %16, i64 %17
  %19 = getelementptr inbounds i64, i64* %18, i64 8
  %20 = icmp ugt i64* %19, %6
  br i1 %20, label %21, label %15

; <label>:21:                                     ; preds = %15, %1
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %11)
  ret i32 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }

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
!8 = !{!9, !9, i64 0}
!9 = !{!"long", !5, i64 0}
