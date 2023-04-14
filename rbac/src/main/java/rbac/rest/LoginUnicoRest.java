package rbac.rest;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.swagger.annotations.Api;
import rbac.dto.Login;
import rbac.dto.TokenRecursoAcao;

@Api
@Path("/loginunico")
public class LoginUnicoRest {
	
	private static Key chavePrivada = null;

	private static Map<String, Map<String, String>> rbac = new HashMap<>();
	
	/** Inicia as regras RBAC utilizando uma chamada ao método estático inicializarRegrasRBAC.*/
	
	static {
		inicializarRegrasRBAC();
	}

	private static void inicializarRegrasRBAC() {
		Map<String, String> perfil_admin = new HashMap<>();
		perfil_admin.put("empregado", "GET,POST,PUT,DELETE");
		perfil_admin.put("usuario", "GET,POST,PUT,DELETE");
		perfil_admin.put("sistema", "GET");

		Map<String, String> perfil_user = new HashMap<>();
		perfil_user.put("empregado", "GET");
		perfil_user.put("sistema", "GET");

		rbac.put("ADMIN", perfil_admin);
		rbac.put("USER", perfil_user);
	}

	/** ####################################################################################################### */
	
	/** adicione o método getPrivateKey, que construirá e retornará a chave privada para geração e validação dos tokens*/
	
	private static Key getPrivateKey() {
		if (chavePrivada == null) {
			String privateKey = "wb8w338e24f11f4692a95738fe2e893c2ab8338e24f11f4e64";
			byte[] keyBytes = Decoders.BASE64.decode(privateKey);
			chavePrivada = Keys.hmacShaKeyFor(keyBytes);
		}
		return chavePrivada;
	}
	
	/** ####################################################################################################### */
	
	/** Adicione o método validarToken que validará os JWTs*/
	
	private static Jws<Claims> validarToken(String tokenJWT) throws Exception {
		try {
			Jws<Claims> declaracoes = Jwts.parserBuilder().setSigningKey(getPrivateKey()).build()
					.parseClaimsJws(tokenJWT);
			return declaracoes;
		} catch (ExpiredJwtException e) {
			throw new RuntimeException("Token expirado!");
		} catch (MalformedJwtException ex) {
			throw new RuntimeException("Token mal formado!");
		}
	}

	/** ####################################################################################################### */
	
	/** Adicione o método gerarToken, que construirá os JWTs*/
	
	public static String gerarToken(String usuario, String perfil) throws Exception {
		Map<String, Object> headers = new HashMap<String, Object>();
		headers.put("typ", "JWT");
		HashMap<String, String> claims = new HashMap<String, String>();
		claims.put("iss", "SSO SISRH");
		claims.put("aud", "Publico");
		claims.put("user", usuario);
		claims.put("perfil", perfil);

		final Date dtCriacao = new Date();
		final Date dtExpiracao = new Date(dtCriacao.getTime() + 1000 * 60 * 15);
		String jwtToken = Jwts.builder().setHeader(headers).setIssuedAt(new Date()).setClaims(claims)
				.setSubject("Acesso RBAC").setIssuedAt(dtCriacao).setExpiration(dtExpiracao).signWith(getPrivateKey())
				.compact();
		return jwtToken;
	}

	/** ####################################################################################################### */
	
	/** Adicione o método que tratará a requisição POST para gerar um JWT ao receber um usuário e senha válidos.*/
	@POST
	@Path("autenticar")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response autenticar(Login login) {
		try {
			if (login.getUsuario().equals("valeria") && login.getSenha().equals("123")) {
				return Response.ok().entity(gerarToken("valeria", "ADMIN")).build();
			}
			if (login.getUsuario().equals("ricardo") && login.getSenha().equals("123")) {
				return Response.ok().entity(gerarToken("ricardo", "USER")).build();
			}
			return Response.status(Status.FORBIDDEN).entity("{ \"mensagem\" : \"Usuario ou senha invalido!\" }")
					.build();

		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(
					"{ \"mensagem\" : \"Falha para gerar token JWT!\" , \"detalhe\" :  \"" + e.getMessage() + "\"  }")
					.build();
		}
	}

	/** ####################################################################################################### */
	
	@POST
	@Path("validar")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response validarToken(TokenRecursoAcao tokenRecurso) {
		try {
			Jws<Claims> declaracores = validarToken(tokenRecurso.getToken());
			String perfil = declaracores.getBody().get("perfil").toString();
			Map<String, String> perfilRBAC = rbac.get(perfil);
			if (perfilRBAC != null && perfilRBAC.get(tokenRecurso.getRecurso()).contains(tokenRecurso.getAcao())) {
				return Response.status(Status.OK).entity("{ \"mensagem\" : \"Acesso autorizado!\" }").build();
			}
		} catch (Exception e) {
			return Response.status(Status.FORBIDDEN).entity("{ \"mensagem\" : \"Acesso negado!\" }").build();
		}
		return Response.status(Status.FORBIDDEN).entity("{ \"mensagem\" : \"Acesso negado!\" }").build();
	}

	
}
