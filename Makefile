NAME = malsnitch
CGO_ENABLED = 1
GO_CFLAGS   = -buildmode=pie -trimpath -mod=readonly -modcacherw
GO_LDFLAGS = -linkmode=external

default: build

build: mod
	go get
	go build $(GO_CFLAGS) -ldflags '$(GO_LDFLAGS)' -o $(NAME)

mod:
	test -f go.mod || ( go mod init $(NAME) && go mod tidy )

clean:
	rm -f $(NAME)

#.SILENT: build mod clean $(NAME)
