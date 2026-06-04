package kr.ac.hansung.controller;

import jakarta.validation.Valid;
import kr.ac.hansung.dto.PasswordChangeDto;
import kr.ac.hansung.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/user/password")
    public String passwordForm(Model model) {

        model.addAttribute("passwordChangeDto",
                new PasswordChangeDto());

        return "user/password";
    }

    @PostMapping("/user/password")
    public String changePassword(
            @Valid @ModelAttribute PasswordChangeDto passwordChangeDto,
            BindingResult bindingResult,
            Authentication authentication,
            RedirectAttributes ra,
            Model model) {

        if (bindingResult.hasErrors()) {
            return "user/password";
        }

        if (!passwordChangeDto.getNewPassword().equals(passwordChangeDto.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "mismatch",
                    "새 비밀번호가 일치하지 않습니다");
            return "user/password";
        }

        try {

            userService.changePassword(
                    authentication.getName(),
                    passwordChangeDto.getCurrentPassword(),
                    passwordChangeDto.getNewPassword()
            );

            ra.addFlashAttribute("successMessage",
                    "비밀번호가 변경되었습니다.");

            return "redirect:/home";

        } catch (IllegalArgumentException e) {

            model.addAttribute("errorMessage",
                    e.getMessage());

            return "user/password";
        }
    }
}