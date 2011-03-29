.PHONY: all compile rel deps doc clean test

all: rel

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

test: all
	@./rebar eunit skip_deps=true