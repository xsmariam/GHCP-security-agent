# Ruby / Rails specifics
- SQL: `where("name = '#{params[:name]}'")`, `find_by_sql`, `order(params[:sort])`, `pluck`/`group` with input.
- Commands/code: backticks, `system`/`exec`/`%x` with interpolation, `Kernel#open` with user input (pipe execution), `eval`, `send`/`public_send`/`constantize` with user-controlled names.
- Deserialization: `Marshal.load`, `YAML.load` (use `safe_load`), `Oj` in object mode.
- Rails: `params.permit!` or missing strong parameters (mass assignment), `skip_before_action :verify_authenticity_token`, missing `before_action` auth, `html_safe`/`raw` on user data, `redirect_to params[:url]`, `render inline:` with input, `render file:` with user paths.
- Crypto: `Digest::MD5/SHA1` for passwords (use `has_secure_password`/bcrypt), `rand` for tokens (use `SecureRandom`), `OpenSSL::SSL::VERIFY_NONE`.
