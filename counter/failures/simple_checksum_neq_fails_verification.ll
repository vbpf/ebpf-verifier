; ModuleID = 'kern/simple_checksum_neq_fails_verification.bc'
source_filename = "kern/simple_checksum_neq_fails_verification.c"
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
  %3 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %3) #2
  store i32 1, i32* %2, align 4, !tbaa !2
  %4 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @m to i8*), i8* nonnull %3) #2
  %5 = icmp eq i8* %4, null
  br i1 %5, label %34, label %6

; <label>:6:                                      ; preds = %1
  %7 = load i8, i8* %4, align 1, !tbaa !6
  %8 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15
  %9 = load i32, i32* %8, align 4, !tbaa !7
  %10 = zext i32 %9 to i64
  %11 = inttoptr i64 %10 to i8*
  %12 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16
  %13 = load i32, i32* %12, align 4, !tbaa !9
  %14 = zext i32 %13 to i64
  %15 = inttoptr i64 %14 to i8*
  %16 = getelementptr inbounds i8, i8* %11, i64 8
  %17 = icmp ult i8* %16, %15
  br i1 %17, label %18, label %29

; <label>:18:                                     ; preds = %6
  %19 = getelementptr i8, i8* %15, i64 -8
  br label %20

; <label>:20:                                     ; preds = %20, %18
  %21 = phi i32 [ 0, %18 ], [ %27, %20 ]
  %22 = phi i8* [ %11, %18 ], [ %26, %20 ]
  %23 = load i8, i8* %22, align 1, !tbaa !6
  %24 = zext i8 %23 to i32
  %25 = add nuw nsw i32 %21, %24
  %26 = getelementptr inbounds i8, i8* %22, i64 1
  %27 = and i32 %25, 255
  %28 = icmp eq i8* %26, %19
  br i1 %28, label %29, label %20

; <label>:29:                                     ; preds = %20, %6
  %30 = phi i32 [ 0, %6 ], [ %27, %20 ]
  %31 = zext i8 %7 to i32
  %32 = icmp ne i32 %30, %31
  %33 = zext i1 %32 to i32
  br label %34

; <label>:34:                                     ; preds = %1, %29
  %35 = phi i32 [ %33, %29 ], [ 1, %1 ]
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %3) #2
  ret i32 %35
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
