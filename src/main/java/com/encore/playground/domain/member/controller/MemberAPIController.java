package com.encore.playground.domain.member.controller;

import com.encore.playground.domain.member.dto.MemberDTO;
import com.encore.playground.domain.member.entity.Member;
import com.encore.playground.domain.member.repository.MemberRepository;
import com.encore.playground.domain.member.service.MemberSecurityService;
import com.encore.playground.domain.member.service.MemberService;
import com.encore.playground.global.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RequestMapping("/api/member")
@RestController
public class MemberAPIController {

    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final MemberSecurityService memberSecurityService;

    /**
     * POST - 로그인 사용자 정보 데이터 전달
     * @param loginMember
     * @return 사용자 토큰 생성
     */

    @PostMapping("login/test")
    public String loginCheck(@RequestBody Map<String, String > loginMember) {
        // 로그인한 사용자의 userid 를 가져와서 사용자 정보를 가져옴
        UserDetails member = memberSecurityService.loadUserByUsername(loginMember.get("userid"));

        if(!passwordEncoder.matches(loginMember.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }

        String userid = member.getUsername();
        String roles = member.getAuthorities().stream().toList().get(0).toString();

        return jwtTokenProvider.generateToken(userid, roles);
    }

    @PostMapping("/login")
    public ResponseEntity loginCheck2(@RequestBody Map<String, String > loginMember) {

        System.out.println("[MemberAPIController:/api/member/login] ::: loginCheck()");

        // TODO : 유저 정보를 확인할 때 Security 를 사용할지 별도로 Service 에 추가해서 확인할지 생각

         UserDetails member = memberSecurityService.loadUserByUsername(loginMember.get("userid"));
//        Member member = memberService.getMemberByUserid(loginMember.get("userid"));
        String userid = member.getUsername();
//        String nickname = member.getNickname();

        // 패스워드가 맞는지 확인한다.
        if(!passwordEncoder.matches(loginMember.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }

        // 로그인해서 아이디 확인하고 패스워드 맞는지 확인 후에 토큰 생성
//        String token = tokenService.generateToken(userid);

        /*
            TODO : 로그인할 때 보내줘야할 데이터 - 아이디, 닉네임, 이메일, 토큰(헤더로 보내기 때문에 이후에 제외해도 될듯)
         */

        // 토큰을 담아보낼 HashMap 생성
        Map<String, String> loginRes = new HashMap<>();
        loginRes.put("userid", userid);
//        loginRes.put("nickname", nickname);
//        loginRes.put("token", token);

        // 헤더에 토큰을 저장한다.
//        HttpHeaders headers = new HttpHeaders();
//        headers.add("Authorization", "Bearer " + token);

        // TODO : statusCode 와 responseMessage 를 어떻게 구분해서 보낼 것인가

        return new ResponseEntity(
                loginRes,
                HttpStatus.OK
        );
    }

    /**
     * POST - Header 에 JWT 데이터 전달
     * @return 토큰 인증이 정상적으로 완료되면 "user ok" 반환
     */

    @PostMapping("/user/test")
    public Map userResponseTest() {
        Map<String, String> result = new HashMap<>();
        result.put("result","user ok");
        return result;
    }

    /**
     * POST - Header 에 JWT 데이터 전달
     * @return 토큰 인증이 정상적으로 완료되면 "admin ok" 반환
     */

    @PostMapping("/admin/test")
    public Map adminResponseTest() {
        Map<String, String> result = new HashMap<>();
        result.put("result","admin ok");
        return result;
    }
}
