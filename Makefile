CURVE ?= BLS381
SMALL_SIGNATURES ?= n
NPROCS ?= 1
NTHREADS ?= 4

.PHONY: test
test: clean
	@echo "== Single Threaded =="
	JULIA_DEBUG=PBC PBC_SMALL_SIGNATURES=$(SMALL_SIGNATURES) RELIC_TOOLKIT_CURVE=$(CURVE) julia --compiled-modules=no --track-allocation=user -e 'import Pkg; Pkg.activate("."); Pkg.test(coverage=true)'
	@echo "== Multi Threaded =="
	JULIA_DEBUG=PBC PBC_NPROCS=$(NPROCS) JULIA_NUM_THREADS=$(NTHREADS) PBC_SMALL_SIGNATURES=$(SMALL_SIGNATURES) RELIC_TOOLKIT_CURVE=$(CURVE) julia --compiled-modules=no --track-allocation=user -e 'import Pkg; Pkg.activate("."); Pkg.test(coverage=true)'

.PHONY: coverage
coverage:
	# julia -e 'using Pkg; Pkg.add("Coverage")' && brew install lcov
	@mkdir -p ./test/coverage
	julia -e 'using Pkg; "Coverage" in keys(Pkg.installed()) || Pkg.add("Coverage"); using Coverage; LCOV.writefile("./test/coverage/lcov.info", process_folder())'
	genhtml -o ./test/coverage ./test/coverage/lcov.info
	open ./test/coverage/index.html

.PHONY: bench
bench:
	PBC_NPROCS=$(NPROCS) JULIA_NUM_THREADS=$(NTHREADS) PBC_SMALL_SIGNATURES=$(SMALL_SIGNATURES) RELIC_TOOLKIT_CURVE=$(CURVE) TEST=PerfTests julia --compiled-modules=no -e 'import Pkg; Pkg.activate("."); Pkg.test()'

.PHONY: profile
profile:
	julia -e 'import Pkg; Pkg.activate("."); Pkg.test()'

.PHONY: clean
clean:
	git clean -fdX
