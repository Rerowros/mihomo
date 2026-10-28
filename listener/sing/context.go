package sing

import (
	"context"
	"golang.org/x/exp/slices"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/auth"
)

type contextKey string

var ctxKeyAdditions = contextKey("Additions")

func WithAdditions(ctx context.Context, additions ...inbound.Addition) context.Context {
	return context.WithValue(ctx, ctxKeyAdditions, additions)
}

func AdditionsFromContext(ctx context.Context) []inbound.Addition { return getAdditions(ctx) }

func getAdditions(ctx context.Context) (additions []inbound.Addition) {
	if v := ctx.Value(ctxKeyAdditions); v != nil {
		if a, ok := v.([]inbound.Addition); ok {
			additions = a
		}
	}
	if user, ok := auth.UserFromContext[string](ctx); ok {
		additions = slices.Clip(additions) // force the subsequent `append()` to copy the slice
		additions = append(additions, inbound.WithInUser(user))
		// Only an authenticated user can have a session; listeners without
		// users skip this lookup.
		if session := inboundSession(ctx); session != nil {
			additions = append(additions, inbound.WithInSession(session))
		}
	}
	return
}

var ctxKeyInboundSession = contextKey("InboundSession")

// WithInboundSession attaches the record of the authenticated user. Every
// stream opened on the connection (mux, XUDP) inherits it with the context.
func WithInboundSession(ctx context.Context, session C.InboundSession) context.Context {
	return context.WithValue(ctx, ctxKeyInboundSession, session)
}

// userSession is the session of the authenticated user, nil without one: only
// an authenticated user can have a session, so connections of listeners
// without users (TUN, mixed) skip the session lookup.
func userSession(ctx context.Context) C.InboundSession {
	if _, ok := auth.UserFromContext[string](ctx); !ok {
		return nil
	}
	return inboundSession(ctx)
}

func inboundSession(ctx context.Context) C.InboundSession {
	if v := ctx.Value(ctxKeyInboundSession); v != nil {
		if session, ok := v.(C.InboundSession); ok {
			return session
		}
	}
	return nil
}

var ctxKeyInAddr = contextKey("InAddr")

func WithInAddr(ctx context.Context, inAddr net.Addr) context.Context {
	return context.WithValue(ctx, ctxKeyInAddr, inAddr)
}

func getInAddr(ctx context.Context) net.Addr {
	if v := ctx.Value(ctxKeyInAddr); v != nil {
		if a, ok := v.(net.Addr); ok {
			return a
		}
	}
	return nil
}
