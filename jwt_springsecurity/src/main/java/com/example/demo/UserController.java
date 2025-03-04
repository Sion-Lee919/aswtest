package com.example.demo;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@RestController
public class UserController {
	
	@Value("${jwt.secretkey}")
	String mykey;
	
	@Autowired
	BCryptPasswordEncoder encoder;
	
	@RequestMapping("/loginjwt/{id}/{pw}")
	@CrossOrigin(origins = "http://localhost:4000")
	public String getUserJwt(@PathVariable("id") String id, @PathVariable("pw") String pw) {
		if(id.equals("user")&&pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
			long expiredTimeMs = 60*60*1000;
			return JwtTokenUtil.createToken(id, mykey, expiredTimeMs); 
			//클라이언트 전송 (그 다음 요청시 서버로 전달되기 위해선 클라이언트측 지속 저장)
			//js(cookie, localStorage, sessionStorage)
		}
		else {
			return "id나 pw 중 하나 비정상";
		}
		
	}
	
	@RequestMapping("/loginjwtheader/{id}/{pw}")
	@CrossOrigin(origins = "http://localhost:4000", exposedHeaders = "Authorization")
	public ResponseEntity<String> getUserJwtHeader(@PathVariable("id") String id, @PathVariable("pw") String pw) {
		if(id.equals("user")&&pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
			long expiredTimeMs = 60*60*1000;
			String genToken = JwtTokenUtil.createToken(id, mykey, expiredTimeMs);
			//응답 AUTHORRIZATION
			HttpHeaders httpheaders = new HttpHeaders();
			httpheaders.add("Authorization","Bearer" + genToken);
			String tokenJson = "{\"jwtToken\":\"Bearer"+ genToken + "\"}";
			return new ResponseEntity<String>(tokenJson,httpheaders,HttpStatus.OK);
		}
		else {
			return new ResponseEntity<String>("id나 pw 중 하나 비정상",HttpStatus.OK);
		}
		
	}
	
	@RequestMapping("/userinfo")
	@CrossOrigin(origins = "http://localhost:4000", allowCredentials = "true")
	public String userinfo(Authentication auth, @AuthenticationPrincipal Users user) {
//			return auth.getName() + " 회원님 "
//					+auth.getAuthorities() + " 의 역할입니다. ";
			String mypw="1111";
			if(encoder.matches(mypw, user.getPassword())) {
			return user.getName() + " 회원님 "
			+"암호는"+user.getPassword() +"이고"+user.getRole()+ " 의 역할입니다. ";
			}
			else {
				return "암호 동일하지 않음";
			}
	}
	
	@RequestMapping("/logoutjwtcookie")
	@CrossOrigin(origins = "http://localhost:4000", allowCredentials = "true")
	public String logout(HttpServletResponse response) {
		Cookie cookie = new Cookie("jwtcookie", null);
		cookie.setMaxAge(0);
		response.addCookie(cookie);
		return "로그아웃하셨습니다.";
		}

	
	@RequestMapping("/loginjwtcookie/{id}/{pw}")
	@CrossOrigin(origins = "http://localhost:4000", allowCredentials = "true")
	public String getUserJwtCookie(@PathVariable("id") String id, @PathVariable("pw") String pw, HttpServletResponse response) {
		if(id.equals("user")&&pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
			long expiredTimeMs = 60*60*1000;
			String genToken = JwtTokenUtil.createToken(id, mykey, expiredTimeMs); 
			Cookie cookie = new Cookie("jwtcookie", genToken);
			cookie.setPath("/");
			cookie.setMaxAge(60*60);
			response.addCookie(cookie);
			return "로그인 성공";
		}
		else {
			return "id나 pw 중 하나 비정상";
		}
		
	}
	
}
