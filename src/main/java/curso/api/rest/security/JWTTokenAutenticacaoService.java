package curso.api.rest.security;

import java.util.Date;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import curso.api.rest.ApplicationContextLoad;
import curso.api.rest.model.Usuario;
import curso.api.rest.repository.UsuarioRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
@Component
public class JWTTokenAutenticacaoService {
	
	/*Tempo de expiração do token*/
	private static final long EXPIRATION_TIME = 172800000;
	
	/*Uma senha unica para compor a autenticação e ajudar na segurança*/
	private static final String SECRET = "*SenhaExtremamenteSecreta";
	
	/*Prefixo padrão de token*/
	private static final String TOKEN_PREFIX = "Bearer";
	
	private static final String HEADER_STRING ="Authorization";
	
	
	/*Gerando token de autenticação e adicionando ao cabeçalho e resposta http*/
	public void addAuthentication(HttpServletResponse response, String username) throws Exception{
		
		/*Montagem do token*/
		String JWT = Jwts.builder()/*CHAMA O GERADOR DE TOKEN*/
				.setSubject(username)/*ADICIONA O USUARIO*/
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))/*TEMPO DE AUTENTICACAO*/
				.signWith(SignatureAlgorithm.HS512, SECRET).compact();/*COMPACTACAO E ALGORITMOS DE GERAÇÃO DE SENHA*/
		
		String token = TOKEN_PREFIX + " " + JWT; /*Bearer 45968494846948*/ /*junta o token com o prefixo*/
		
		/*Adiciona no cabeçalho http*/
		response.addHeader(HEADER_STRING, token); /*Authorization: Bearer 45968494846948 */
		
		/*Escreve token como resposta no corpo http*/
		response.getWriter().write("{\"Authorization\": \""+token+"\"}");
			
	}
	
	/*retorna o usuario validado com token ou caso nao seja valido retorna null*/
	public Authentication getAuthentication(HttpServletRequest request) {
		
		/*pega o token enviado no cabeçalho http*/
		
		String token = request.getHeader(HEADER_STRING);
		
		if (token != null) {
			
			/*faz a validacao do token do usuario na requisição*/
			
			String user = Jwts.parser().setSigningKey(SECRET)/*Bearer 45968494846948*/
					.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))/*45968494846948*/
					.getBody().getSubject();/*UsuarioDjalmaDutra*/
			
			if(user != null) {
				
				Usuario usuario = ApplicationContextLoad.getApplicationContext()
						.getBean(UsuarioRepository.class).findUserByLogin(user);
				
				if (user != null) {
					return new UsernamePasswordAuthenticationToken(usuario.getLogin(), 
																	usuario.getSenha(), 
																	usuario.getAuthorities());
					}
				}
			}
			return null; /*nao autorizado*/
		
	}
	
	

}
