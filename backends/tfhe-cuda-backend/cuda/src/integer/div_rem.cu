#include "integer/div_rem.cuh"

void scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
    void *stream, uint32_t gpu_index, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory) {

#ifdef BENCH_SCRATCH_LEVEL_1
  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);

  // Record start time
  cudaEventRecord(start, static_cast<cudaStream_t>(stream));
#endif

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_div_rem_kb<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      (int_div_rem_memory<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);

#ifdef BENCH_SCRATCH_LEVEL_1
  cudaEventRecord(stop, static_cast<cudaStream_t>(stream));
  cudaEventSynchronize(stop);

  float milliseconds = 0;
  cudaEventElapsedTime(&milliseconds, start, stop);
  printf("Time for scratch operations: %.3f ms\n", milliseconds);
#endif

}

void cuda_integer_div_rem_radix_ciphertext_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, void *quotient,
    void *remainder, void *numerator, void *divisor, int8_t *mem_ptr, void *bsk,
    void *ksk, uint32_t num_blocks) {

  auto stream_array = (cudaStream_t *)(streams);
  auto cur_stream = stream_array[0];
#ifdef BENCH_HOST_LEVEL_1
  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);

  // Record start time
  cudaEventRecord(start, cur_stream);
#endif
  auto mem = (int_div_rem_memory<uint64_t> *)mem_ptr;

  switch (mem->params.polynomial_size) {
  case 512:
    host_integer_div_rem_kb<uint64_t, Degree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  case 1024:

    host_integer_div_rem_kb<uint64_t, Degree<1024>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  case 2048:
    host_integer_div_rem_kb<uint64_t, Degree<2048>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  case 4096:
    host_integer_div_rem_kb<uint64_t, Degree<4096>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  case 8192:
    host_integer_div_rem_kb<uint64_t, Degree<8192>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  case 16384:
    host_integer_div_rem_kb<uint64_t, Degree<16384>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(quotient), static_cast<uint64_t *>(remainder),
        static_cast<uint64_t *>(numerator), static_cast<uint64_t *>(divisor),
        bsk, static_cast<uint64_t *>(ksk), mem, num_blocks);
    break;
  default:
    PANIC("Cuda error (integer div_rem): unsupported polynomial size. "
          "Only N = 512, 1024, 2048, 4096, 8192, 16384 is supported")
  }

#ifdef BENCH_HOST_LEVEL_1
  cudaEventRecord(stop, cur_stream);
  cudaEventSynchronize(stop);

  float milliseconds = 0;
  cudaEventElapsedTime(&milliseconds, start, stop);
  printf("Time for host operations: %.3f ms\n", milliseconds);
#endif

}

void cleanup_cuda_integer_div_rem(void *stream, uint32_t gpu_index,
                                  int8_t **mem_ptr_void) {
#ifdef BENCH_DROP_LEVEL_1
  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);

  // Record start time
  cudaEventRecord(start, static_cast<cudaStream_t>(stream));
#endif
  int_div_rem_memory<uint64_t> *mem_ptr =
      (int_div_rem_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(static_cast<cudaStream_t>(stream), gpu_index);

#ifdef BENCH_DROP_LEVEL_1
  cudaEventRecord(stop, static_cast<cudaStream_t>(stream));
  cudaEventSynchronize(stop);

  float milliseconds = 0;
  cudaEventElapsedTime(&milliseconds, start, stop);
  printf("Time for drop operations: %.3f ms\n", milliseconds);
#endif
}
