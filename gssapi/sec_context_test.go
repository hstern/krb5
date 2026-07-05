package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecContextWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()

	initiator := NewSecContext(getSessionKey(), nil, true, false, 0)
	acceptor := NewSecContext(getSessionKey(), nil, false, false, 0)

	wt, err := initiator.Wrap([]byte("hello world"))
	require.NoError(t, err)

	ok, err := acceptor.Unwrap(wt)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestSecContextUnwrapRejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	initiator := NewSecContext(getSessionKey(), nil, true, false, 0)
	acceptor := NewSecContext(getSessionKey(), nil, false, false, 0)

	wt, err := initiator.Wrap([]byte("hello world"))
	require.NoError(t, err)

	wt.Payload = []byte("hEllo world")

	ok, _ := acceptor.Unwrap(wt)
	assert.False(t, ok)
}

func TestSecContextMICVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	initiator := NewSecContext(getSessionKey(), nil, true, false, 0)
	acceptor := NewSecContext(getSessionKey(), nil, false, false, 0)

	mt, err := initiator.MIC([]byte("signed data"))
	require.NoError(t, err)

	ok, err := acceptor.VerifyMIC([]byte("signed data"), mt)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _ = acceptor.VerifyMIC([]byte("different data"), mt)
	assert.False(t, ok)
}

func TestSecContextUnwrapRejectsWrongSenderRole(t *testing.T) {
	t.Parallel()

	initiator := NewSecContext(getSessionKey(), nil, true, false, 0)
	peerInitiator := NewSecContext(getSessionKey(), nil, true, false, 0)

	// A token wrapped by an initiator must not be accepted by another context
	// that also expects to receive from the acceptor.
	wt, err := initiator.Wrap([]byte("hello"))
	require.NoError(t, err)

	_, err = peerInitiator.Unwrap(wt)
	require.Error(t, err)
}

func TestSecContextSetsAcceptorSubkeyFlag(t *testing.T) {
	t.Parallel()

	// An acceptor keyed with its own subkey stamps both the acceptor bit (0x01)
	// and the acceptor-subkey bit (0x04) on the tokens it sends.
	acceptor := NewSecContext(getSessionKey(), nil, false, true, 0)

	wt, err := acceptor.Wrap([]byte("hi"))
	require.NoError(t, err)
	assert.Equal(t, byte(MICTokenFlagSentByAcceptor|MICTokenFlagAcceptorSubkey), wt.Flags)

	mt, err := acceptor.MIC([]byte("hi"))
	require.NoError(t, err)
	assert.Equal(t, byte(MICTokenFlagSentByAcceptor|MICTokenFlagAcceptorSubkey), mt.Flags)
}

func TestSecContextWrapStampsIncrementingSequence(t *testing.T) {
	t.Parallel()

	initiator := NewSecContext(getSessionKey(), nil, true, false, 5)

	wt1, err := initiator.Wrap([]byte("a"))
	require.NoError(t, err)
	assert.Equal(t, uint64(5), wt1.SndSeqNum)

	wt2, err := initiator.Wrap([]byte("b"))
	require.NoError(t, err)
	assert.Equal(t, uint64(6), wt2.SndSeqNum)
}
