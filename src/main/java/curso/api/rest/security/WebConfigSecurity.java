package curso.api.rest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import curso.api.rest.service.ImplementacaoUserDetailService;

@Configuration
@EnableWebSecurity
/*Mapeia URL, endereços, autoriza ou bloqueia acesso a URL*/
public class WebConfigSecurity extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private ImplementacaoUserDetailService implementacaoUserDetailService;
	
	/*Configura as solicitações de acesso por http*/
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		/*ativando a proteção contra usuario que nao estao validados por token*/
		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		/*Ativando a restrição a URL*/
		.disable().authorizeRequests().antMatchers("/").permitAll()
		/*URL de logout - redireciona apos o user deslogar do sistema*/
		.anyRequest().authenticated().and().logout().logoutSuccessUrl("/")
		/*Mapeia URL de logout e invalida o usuario*/
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		/*Filtra requisições de login para autenticação*/
		
		/*Filtra demais requisições para verificar a presenção do TOKEN JWT no HEADER HTTP*/
		
		;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		/*Service que ira consultar o usuario no banco de dados*/
		auth.userDetailsService(implementacaoUserDetailService)
		/*Padrão de codificação de senha*/
		.passwordEncoder(new BCryptPasswordEncoder());
	}
	

}
