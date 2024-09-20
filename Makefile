EXE=ldapproxy
MAINFILE=proxy.go

$(EXE): ./*.go
	go build -o $(EXE) $(MAINFILE)

.PHONY: clean
clean:
	rm $(EXE)
