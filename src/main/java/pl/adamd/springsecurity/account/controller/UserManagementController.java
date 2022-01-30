package pl.adamd.springsecurity.account.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.adamd.springsecurity.account.dao.User;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/users")
class UserManagementController {
    private static final List<User> USERS = Arrays.asList(
            new User(1, "Johny"),
            new User(2, "Mickey"),
            new User(3, "Bruce")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<User> getAllUsers(){
        System.out.println("\ngetAllUsers");
        return USERS ;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user:write')")
    public void registerNewUser(@RequestBody User user){
        System.out.println("\nregisterNewUser:");
        System.out.println(user);
    }

    @DeleteMapping(path = "{id}")
    @PreAuthorize("hasAuthority('user:write')")
    public void deleteUser(@PathVariable("id") Integer id){
        System.out.println("\ndeleteUser:");
        System.out.println(id);
    }

    @PutMapping(path = "{id}")
    @PreAuthorize("hasAuthority('user:write')")
    public void updateStudent(@PathVariable("id")Integer id, User user){
        System.out.println("\nupdateStudent:");
        System.out.printf("%s %s%n", id, user);
    }

}
