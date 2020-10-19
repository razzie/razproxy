package razproxy

// RPC ...
type RPC struct {
	session *serverSession
}

// Auth is an RPC function to authenticate the client
func (rpc *RPC) Auth(req *AuthRequest, result *AuthResult) error {
	result.ID, result.OK = rpc.session.auth(req.User, req.Password)
	return nil
}

// AuthRequest ...
type AuthRequest struct {
	User     string
	Password string
}

// AuthResult ...
type AuthResult struct {
	OK bool
	ID string
}
