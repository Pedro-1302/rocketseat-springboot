package br.com.pedrofranco.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.pedrofranco.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Toda requisição passa primeiro pelo filtro 
@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository iUserRepository; 

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servletPath = request.getServletPath(); 

        if (servletPath.startsWith("/tasks/")) { 
        // Pegar a autenticação (usuario e senha)
        var authorization = request.getHeader("Authorization"); 

        var authEncoded = authorization.substring("Basic".length()).trim();

        byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

        var authString = new String(authDecoded);  

        // [PedroGames123], [pedraogames@123]
        String[] credentials = authString.split(":"); 
        String username = credentials[0];
        String password = credentials[1]; 
        
        var user = this.iUserRepository.findByUsername(username); 

        if (user == null) { 
            response.sendError(401, "Usuário sem autorização");
        } else { 

            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

            if (passwordVerify.verified) { 
                request.setAttribute("idUser", user.getId());
                filterChain.doFilter(request, response);
            } else { 
                response.sendError(401, "Senha não confere");
            }

        }
        } else { 
            filterChain.doFilter(request, response);
        }

    }

}
