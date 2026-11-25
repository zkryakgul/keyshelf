package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/zkryakgul/keyshelf/internal/store"
)

// ---- public ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ store.Token) {
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": s.st.Initialized(), "sealed": s.st.Sealed()})
}

func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request, _ store.Token) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.credential(w, s.unseal, func() error { return s.st.Unseal([]byte(body.Passphrase)) })
	if !ok {
		return
	}
	if err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			s.audit(r, "anonymous", "unseal.fail", "")
		}
		s.storeError(w, err)
		return
	}
	s.audit(r, "anonymous", "unseal", "")
	writeJSON(w, http.StatusOK, map[string]bool{"sealed": false})
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request, _ store.Token) {
	var body struct {
		RecoveryCode  string `json:"recovery_code"`
		NewPassphrase string `json:"new_passphrase"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.credential(w, s.unseal, func() error {
		return s.st.Recover(body.RecoveryCode, []byte(body.NewPassphrase))
	})
	if !ok {
		return
	}
	if err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			s.audit(r, "anonymous", "recover.fail", "")
		}
		s.storeError(w, err)
		return
	}
	s.audit(r, "anonymous", "recover", "")
	writeJSON(w, http.StatusOK, map[string]bool{"sealed": false})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ store.Token) {
	var body struct {
		Password string `json:"password"`
		TOTP     string `json:"totp"`
		Cookie   bool   `json:"cookie"` // web UI: set an HttpOnly cookie instead of returning the token
	}
	if !decode(w, r, &body) {
		return
	}
	if s.opts.RequireTOTP && !s.st.TOTPEnabled() {
		writeError(w, http.StatusForbidden, "TOTP must be set up (from the local machine) before logging in over the network")
		return
	}
	ok, err := s.credential(w, s.login, func() error {
		if err := s.st.CheckOwnerPassword([]byte(body.Password)); err != nil {
			return err
		}
		if s.st.TOTPEnabled() {
			if body.TOTP == "" {
				return store.ErrBadCredentials
			}
			return s.st.CheckTOTP(body.TOTP)
		}
		return nil
	})
	if !ok {
		return
	}
	if err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			s.audit(r, "anonymous", "login.fail", "")
			msg := "wrong password"
			if s.st.TOTPEnabled() {
				msg = "wrong password or TOTP code"
			}
			writeError(w, http.StatusUnauthorized, msg)
			return
		}
		s.storeError(w, err)
		return
	}
	secret, tok, err := s.st.CreateOwnerSession(s.opts.SessionTTL)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "owner", "login", "")
	if body.Cookie {
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: secret, Path: "/api/", Expires: *tok.ExpiresAt,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
		})
		writeJSON(w, http.StatusOK, map[string]any{"csrf": csrfFor(secret), "expires_at": tok.ExpiresAt})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": secret, "expires_at": tok.ExpiresAt})
}

// ---- any token ----

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, tok store.Token) {
	if err := s.st.RevokeToken(tok.ID); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "logout", "")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/api/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleFolders(w http.ResponseWriter, r *http.Request, tok store.Token) {
	all, err := s.st.ListFolders()
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := []store.Folder{}
	for _, f := range all {
		if tok.Allows(store.PermList, f.Path) {
			out = append(out, f)
		}
	}
	s.audit(r, tok.Actor(), "list.folders", "")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListEntries(w http.ResponseWriter, r *http.Request, tok store.Token) {
	q := r.URL.Query()
	folder := q.Get("folder")
	recursive := q.Get("recursive") == "1" || q.Get("recursive") == "true"
	var entries []store.Entry
	var err error
	target := folder
	switch {
	case q.Get("q") != "":
		target = "search"
		entries, err = s.st.Search(q.Get("q"))
	case folder == "" && recursive:
		// "Everything I can see": filtered below, no permission on the root needed.
		entries, err = s.st.ListEntries("", true)
	default:
		if err := store.ValidateFolder(folder); err != nil {
			s.storeError(w, err)
			return
		}
		if !s.allow(w, r, tok, store.PermList, folder, folder) {
			return
		}
		entries, err = s.st.ListEntries(folder, recursive)
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := []store.Entry{}
	for _, e := range entries {
		if tok.Allows(store.PermList, e.Folder) {
			out = append(out, e)
		}
	}
	s.audit(r, tok.Actor(), "list.entries", target)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	if !ok || !s.allow(w, r, tok, store.PermList, folder, path) {
		return
	}
	e, err := s.st.GetEntry(path)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "entry.view", path)
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handlePutEntry(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	if !ok || !s.allow(w, r, tok, store.PermWrite, folder, path) {
		return
	}
	var in store.EntryInput
	if !decode(w, r, &in) {
		return
	}
	in.Ref = path
	if err := s.st.PutEntry(in, tok.Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "entry.put", path)
	e, err := s.st.GetEntry(path)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	if !ok || !s.allow(w, r, tok, store.PermWrite, folder, path) {
		return
	}
	if err := s.st.DeleteEntry(path, tok.Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "entry.delete", path)
	w.WriteHeader(http.StatusNoContent)
}

func fieldParam(r *http.Request) string {
	if f := r.URL.Query().Get("field"); f != "" {
		return f
	}
	return store.DefaultField
}

func (s *Server) handleGetValue(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	field := fieldParam(r)
	if !ok || !s.allow(w, r, tok, store.PermRead, folder, path+"#"+field) {
		return
	}
	v, err := s.st.GetField(path, field)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "value.read", path+"#"+field)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Write(v)
}

func (s *Server) handlePutValue(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	field := fieldParam(r)
	if !ok || !s.allow(w, r, tok, store.PermWrite, folder, path+"#"+field) {
		return
	}
	v, err := io.ReadAll(http.MaxBytesReader(w, r.Body, store.MaxValueSize))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "value too large")
		return
	}
	if err := s.st.SetField(path, field, v, tok.Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "value.write", path+"#"+field)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteValue(w http.ResponseWriter, r *http.Request, tok store.Token) {
	path, folder, ok := pathFolder(w, r)
	field := fieldParam(r)
	if !ok || !s.allow(w, r, tok, store.PermWrite, folder, path+"#"+field) {
		return
	}
	if err := s.st.DeleteField(path, field, tok.Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "value.delete", path+"#"+field)
	w.WriteHeader(http.StatusNoContent)
}

// ---- owner only ----

// handleSession tells the web UI whether its cookie is still good and gives it the CSRF token again
// after a page reload.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, tok store.Token) {
	secret, _ := credentials(r)
	writeJSON(w, http.StatusOK, map[string]any{"csrf": csrfFor(secret), "expires_at": tok.ExpiresAt,
		"sealed": s.st.Sealed(), "totp_enabled": s.st.TOTPEnabled()})
}

func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request, tok store.Token) {
	s.st.Seal()
	s.audit(r, tok.Actor(), "seal", "")
	writeJSON(w, http.StatusOK, map[string]bool{"sealed": true})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, tok store.Token) {
	list, err := s.st.ListAgentTokens()
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var body struct {
		Name       string        `json:"name"`
		Scopes     []store.Scope `json:"scopes"`
		TTLSeconds int64         `json:"ttl_seconds"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, "ttl_seconds must not be negative")
		return
	}
	secret, created, err := s.st.CreateAgentToken(body.Name, body.Scopes, time.Duration(body.TTLSeconds)*time.Second)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "token.create", body.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"token": secret, "info": created})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, tok store.Token) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := s.st.RevokeToken(id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "token.revoke", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, tok store.Token) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.st.ListAudit(store.AuditFilter{Target: r.URL.Query().Get("target"), Limit: limit})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handlePassphrase(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.credential(w, s.unseal, func() error {
		return s.st.ChangePassphrase([]byte(body.Old), []byte(body.New))
	})
	if !ok {
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "passphrase.change", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.credential(w, s.login, func() error {
		if err := s.st.CheckOwnerPassword([]byte(body.Old)); err != nil {
			return err
		}
		return s.st.SetOwnerPassword([]byte(body.New))
	})
	if !ok {
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "password.change", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, tok store.Token) {
	uri, err := s.st.BeginTOTP()
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"otpauth_uri": uri})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.credential(w, s.login, func() error { return s.st.ConfirmTOTP(body.Code) })
	if !ok {
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, tok.Actor(), "totp.enable", "")
	w.WriteHeader(http.StatusNoContent)
}
