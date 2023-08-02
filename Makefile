CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
I_FLAGS = -I ./include
DEP_IFLAGS = -I ./sha3/include -I ./subtle/include

all: test

tests/test_polynomial.o: tests/test_polynomial.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_poly_matrix.o: tests/test_poly_matrix.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_pke.o: tests/test_pke.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_kem.o: tests/test_kem.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/a.out: tests/test_polynomial.o tests/test_poly_matrix.o tests/test_pke.o tests/test_kem.o
	$(CXX) $(OPT_FLAGS) $^ -lgtest -lgtest_main -o $@

test: tests/a.out
	./$<

benchmarks/bench.out: benchmarks/bench_kem.cpp include/*.hpp
	# If your google-benchmark library is not built with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) $< -lbenchmark -lpthread -lbenchmark_main -o $@

benchmarks/perf.out: benchmarks/bench_kem.cpp include/*.hpp
	# Must use this if your google-benchmark library is built with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) $< -lbenchmark -lpthread -lpfm -lbenchmark_main -o $@

benchmark: benchmarks/bench.out
	./$< --benchmark_min_warmup_time=.5 --benchmark_time_unit=us --benchmark_counters_tabular=true

perf: benchmarks/perf.out
	./$< --benchmark_min_warmup_time=.5 --benchmark_time_unit=us --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -maxdepth 2 -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i
