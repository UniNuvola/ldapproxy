EXE=ldapproxy

.PHONY: all
all: $(EXE)

$(EXE): cmd/*.go
	cd cmd/ && go mod tidy && \
	CGO_ENABLED=0 go build && \
	mv cmd ../$(EXE)

.PHONY: clean
clean:
	rm -f $(EXE)
