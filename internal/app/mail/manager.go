package mail

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/compressed"

	"github.com/h44z/wg-portal/internal/config"
	"github.com/h44z/wg-portal/internal/domain"
)

// region dependencies

type Mailer interface {
	// Send sends an email with the given subject and body to the given recipients.
	Send(ctx context.Context, subject, body string, to []string, options *domain.MailOptions) error
}

type ConfigFileManager interface {
	// GetInterfaceConfig returns the configuration for the given interface.
	GetInterfaceConfig(ctx context.Context, id domain.InterfaceIdentifier) (io.Reader, error)
	// GetPeerConfig returns the configuration for the given peer.
	GetPeerConfig(ctx context.Context, id domain.PeerIdentifier) (io.Reader, error)
	// GetPeerConfigQrCode returns the QR code for the given peer.
	GetPeerConfigQrCode(ctx context.Context, id domain.PeerIdentifier) (io.Reader, error)
}

type UserDatabaseRepo interface {
	// GetUser returns the user with the given identifier.
	GetUser(ctx context.Context, id domain.UserIdentifier) (*domain.User, error)
}

type WireguardDatabaseRepo interface {
	// GetInterfaceAndPeers returns the interface and all peers for the given interface identifier.
	GetInterfaceAndPeers(ctx context.Context, id domain.InterfaceIdentifier) (*domain.Interface, []domain.Peer, error)
	// GetPeer returns the peer with the given identifier.
	GetPeer(ctx context.Context, id domain.PeerIdentifier) (*domain.Peer, error)
	// GetInterface returns the interface with the given identifier.
	GetInterface(ctx context.Context, id domain.InterfaceIdentifier) (*domain.Interface, error)
}

type TemplateRenderer interface {
	// GetConfigMail returns the text and html template for the mail with a link.
	GetConfigMail(user *domain.User, link string) (io.Reader, io.Reader, error)
	// GetConfigMailWithAttachment returns the text and html template for the mail with an attachment.
	GetConfigMailWithAttachment(user *domain.User, cfgName, qrName string) (
		io.Reader,
		io.Reader,
		error,
	)
}

// endregion dependencies

type Manager struct {
	cfg *config.Config

	tplHandler  TemplateRenderer
	mailer      Mailer
	configFiles ConfigFileManager
	users       UserDatabaseRepo
	wg          WireguardDatabaseRepo
}

// NewMailManager initializes and returns a new Manager for handling WireGuard configuration email operations.
// Returns an error if the template handler cannot be initialized.
func NewMailManager(
	cfg *config.Config,
	mailer Mailer,
	configFiles ConfigFileManager,
	users UserDatabaseRepo,
	wg WireguardDatabaseRepo,
) (*Manager, error) {
	tplHandler, err := newTemplateHandler(cfg.Web.ExternalUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize template handler: %w", err)
	}

	m := &Manager{
		cfg:         cfg,
		tplHandler:  tplHandler,
		mailer:      mailer,
		configFiles: configFiles,
		users:       users,
		wg:          wg,
	}

	return m, nil
}

// SendPeerEmail sends an email to the user linked to the given peers.
func (m Manager) SendPeerEmail(ctx context.Context, linkOnly bool, privKeys map[string]string, peers ...domain.PeerIdentifier) error {
	for _, peerId := range peers {
		peer, err := m.wg.GetPeer(ctx, peerId)
		if err != nil {
			return fmt.Errorf("failed to fetch peer %s: %w", peerId, err)
		}

		if err := domain.ValidateUserAccessRights(ctx, peer.UserIdentifier); err != nil {
			return err
		}

		if peer.UserIdentifier == "" {
			slog.Debug("skipping peer email",
				"peer", peerId,
				"reason", "no user linked")
			continue
		}

		user, err := m.users.GetUser(ctx, peer.UserIdentifier)
		if err != nil {
			slog.Debug("skipping peer email",
				"peer", peerId,
				"reason", "unable to fetch user",
				"error", err)
			continue
		}

		if pk, ok := privKeys[string(peerId)]; ok {
			peer.Interface.PrivateKey = pk
		}

		if user.Email == "" {
			slog.Debug("skipping peer email",
				"peer", peerId,
				"reason", "user has no mail address")
			continue
		}

		err = m.sendPeerEmail(ctx, linkOnly, user, peer)
		if err != nil {
			return fmt.Errorf("failed to send peer email for %s: %w", peerId, err)
		}
	}

	return nil
}

func (m Manager) sendPeerEmail(ctx context.Context, linkOnly bool, user *domain.User, peer *domain.Peer) error {
	qrName := "WireGuardQRCode.png"
	configName := peer.GetConfigFileName()

	var (
		txtMail, htmlMail io.Reader
		err               error
		mailOptions       domain.MailOptions
	)
	if linkOnly {
		txtMail, htmlMail, err = m.tplHandler.GetConfigMail(user, "deep link TBD")
		if err != nil {
			return fmt.Errorf("failed to get mail body: %w", err)
		}

	} else {
		peerConfig, err := m.tplHandler.GetPeerConfig(peer)
		if err != nil {
			return fmt.Errorf("failed to get peer config for %s: %w", peer.Identifier, err)
		}

		peerConfigQr, err := generatePeerQr(peerConfig)
		if err != nil {
			return fmt.Errorf("failed to generate peer config QR code for %s: %w", peer.Identifier, err)
		}

		txtMail, htmlMail, err = m.tplHandler.GetConfigMailWithAttachment(user, configName, qrName)
		if err != nil {
			return fmt.Errorf("failed to get full mail body: %w", err)
		}

		mailOptions.Attachments = append(mailOptions.Attachments, domain.MailAttachment{
			Name:        configName,
			ContentType: "text/plain",
			Data:        peerConfig,
			Embedded:    false,
		})
		mailOptions.Attachments = append(mailOptions.Attachments, domain.MailAttachment{
			Name:        qrName,
			ContentType: "image/png",
			Data:        peerConfigQr,
			Embedded:    true,
		})
	}

	txtMailStr, _ := io.ReadAll(txtMail)
	htmlMailStr, _ := io.ReadAll(htmlMail)
	mailOptions.HtmlBody = string(htmlMailStr)

	err = m.mailer.Send(ctx, "WireGuard VPN Configuration", string(txtMailStr), []string{user.Email}, &mailOptions)
	if err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}

	return nil
}

// generatePeerQr creates a QR code image from WireGuard configuration data, excluding comment lines.
// The resulting QR code is returned as an io.Reader containing a compressed PNG image.
func generatePeerQr(cfgData io.Reader) (io.Reader, error) {
	sb := strings.Builder{}
	scanner := bufio.NewScanner(cfgData)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "#") {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	code, err := qrcode.NewWith(sb.String(), qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionLow), qrcode.WithEncodingMode(qrcode.EncModeByte))
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	wr := nopCloser{Writer: buf}
	option := compressed.Option{Padding: 8, BlockSize: 4}
	qrWriter := compressed.NewWithWriter(wr, &option)
	if err := code.Save(qrWriter); err != nil {
		return nil, err
	}
	return buf, nil
}
