package pl.adamd.springsecurity.account.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.adamd.springsecurity.account.dao.User;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/users")
class UserController {

    private static final List<User> USERS = Arrays.asList(
            new User(1, "Johny"),
            new User(2, "Mickey"),
            new User(3, "Bruce")
    );

    @GetMapping(path = "{id}")
    public User getUser(@PathVariable("id") Integer userId){
        return USERS.stream()
                .filter(user -> userId.equals(user.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("User " + userId + " does not exists"));
    }
}
