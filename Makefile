.PHONY: all compile rel deps doc clean test

all: deps rel

compile:
	@./rebar compile

rel:
	@./rebar compile generate

deps:
	@./rebar get-deps

doc:
	@./rebar doc skip_deps=true

clean:
	@./rebar clean
	@rm -rf rel/dnsxd

test:
	@./rebar eunit skip_deps=true