// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv32 -target-feature +f -target-feature +d -target-feature +experimental-v \
// RUN:   -disable-O0-optnone -emit-llvm %s -o - | opt -S -mem2reg | FileCheck --check-prefix=CHECK-RV32 %s
// RUN: %clang_cc1 -triple riscv64 -target-feature +f -target-feature +d -target-feature +experimental-v \
// RUN:   -disable-O0-optnone -emit-llvm %s -o - | opt -S -mem2reg | FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV32-LABEL: @test_vfmv_f_s_f32mf2_f32(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv1f32(<vscale x 1 x float> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret float [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f32mf2_f32(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv1f32(<vscale x 1 x float> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret float [[TMP0]]
//
float test_vfmv_f_s_f32mf2_f32(vfloat32mf2_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f32mf2(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfmv.s.f.nxv1f32.i32(<vscale x 1 x float> [[DST:%.*]], float [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f32mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfmv.s.f.nxv1f32.i64(<vscale x 1 x float> [[DST:%.*]], float [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
vfloat32mf2_t test_vfmv_s_f_f32mf2(vfloat32mf2_t dst, float src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f32m1_f32(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv2f32(<vscale x 2 x float> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret float [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f32m1_f32(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv2f32(<vscale x 2 x float> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret float [[TMP0]]
//
float test_vfmv_f_s_f32m1_f32(vfloat32m1_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f32m1(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfmv.s.f.nxv2f32.i32(<vscale x 2 x float> [[DST:%.*]], float [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f32m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfmv.s.f.nxv2f32.i64(<vscale x 2 x float> [[DST:%.*]], float [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfmv_s_f_f32m1(vfloat32m1_t dst, float src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f32m2_f32(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv4f32(<vscale x 4 x float> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret float [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f32m2_f32(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv4f32(<vscale x 4 x float> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret float [[TMP0]]
//
float test_vfmv_f_s_f32m2_f32(vfloat32m2_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f32m2(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfmv.s.f.nxv4f32.i32(<vscale x 4 x float> [[DST:%.*]], float [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f32m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfmv.s.f.nxv4f32.i64(<vscale x 4 x float> [[DST:%.*]], float [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
vfloat32m2_t test_vfmv_s_f_f32m2(vfloat32m2_t dst, float src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f32m4_f32(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv8f32(<vscale x 8 x float> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret float [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f32m4_f32(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv8f32(<vscale x 8 x float> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret float [[TMP0]]
//
float test_vfmv_f_s_f32m4_f32(vfloat32m4_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f32m4(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfmv.s.f.nxv8f32.i32(<vscale x 8 x float> [[DST:%.*]], float [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f32m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfmv.s.f.nxv8f32.i64(<vscale x 8 x float> [[DST:%.*]], float [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
vfloat32m4_t test_vfmv_s_f_f32m4(vfloat32m4_t dst, float src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f32m8_f32(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv16f32(<vscale x 16 x float> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret float [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f32m8_f32(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call float @llvm.riscv.vfmv.f.s.nxv16f32(<vscale x 16 x float> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret float [[TMP0]]
//
float test_vfmv_f_s_f32m8_f32(vfloat32m8_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f32m8(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfmv.s.f.nxv16f32.i32(<vscale x 16 x float> [[DST:%.*]], float [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f32m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfmv.s.f.nxv16f32.i64(<vscale x 16 x float> [[DST:%.*]], float [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
vfloat32m8_t test_vfmv_s_f_f32m8(vfloat32m8_t dst, float src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f64m1_f64(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv1f64(<vscale x 1 x double> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret double [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f64m1_f64(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv1f64(<vscale x 1 x double> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret double [[TMP0]]
//
double test_vfmv_f_s_f64m1_f64(vfloat64m1_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f64m1(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfmv.s.f.nxv1f64.i32(<vscale x 1 x double> [[DST:%.*]], double [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfmv.s.f.nxv1f64.i64(<vscale x 1 x double> [[DST:%.*]], double [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfmv_s_f_f64m1(vfloat64m1_t dst, double src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f64m2_f64(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv2f64(<vscale x 2 x double> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret double [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f64m2_f64(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv2f64(<vscale x 2 x double> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret double [[TMP0]]
//
double test_vfmv_f_s_f64m2_f64(vfloat64m2_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f64m2(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfmv.s.f.nxv2f64.i32(<vscale x 2 x double> [[DST:%.*]], double [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f64m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfmv.s.f.nxv2f64.i64(<vscale x 2 x double> [[DST:%.*]], double [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
vfloat64m2_t test_vfmv_s_f_f64m2(vfloat64m2_t dst, double src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f64m4_f64(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv4f64(<vscale x 4 x double> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret double [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f64m4_f64(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv4f64(<vscale x 4 x double> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret double [[TMP0]]
//
double test_vfmv_f_s_f64m4_f64(vfloat64m4_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f64m4(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfmv.s.f.nxv4f64.i32(<vscale x 4 x double> [[DST:%.*]], double [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f64m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfmv.s.f.nxv4f64.i64(<vscale x 4 x double> [[DST:%.*]], double [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
vfloat64m4_t test_vfmv_s_f_f64m4(vfloat64m4_t dst, double src, size_t vl) {
  return vfmv_s(dst, src, vl);
}

// CHECK-RV32-LABEL: @test_vfmv_f_s_f64m8_f64(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv8f64(<vscale x 8 x double> [[SRC:%.*]])
// CHECK-RV32-NEXT:    ret double [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_f_s_f64m8_f64(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call double @llvm.riscv.vfmv.f.s.nxv8f64(<vscale x 8 x double> [[SRC:%.*]])
// CHECK-RV64-NEXT:    ret double [[TMP0]]
//
double test_vfmv_f_s_f64m8_f64(vfloat64m8_t src) { return vfmv_f(src); }

// CHECK-RV32-LABEL: @test_vfmv_s_f_f64m8(
// CHECK-RV32-NEXT:  entry:
// CHECK-RV32-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfmv.s.f.nxv8f64.i32(<vscale x 8 x double> [[DST:%.*]], double [[SRC:%.*]], i32 [[VL:%.*]])
// CHECK-RV32-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
// CHECK-RV64-LABEL: @test_vfmv_s_f_f64m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfmv.s.f.nxv8f64.i64(<vscale x 8 x double> [[DST:%.*]], double [[SRC:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
vfloat64m8_t test_vfmv_s_f_f64m8(vfloat64m8_t dst, double src, size_t vl) {
  return vfmv_s(dst, src, vl);
}
