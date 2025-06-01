package com.rizvi.learn.spring.security.resources;



import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(TodoResource.class);
    private static final List<Todo> TODOS_LIST = List.of(new Todo("syed", "Learn AWS"),
            new Todo("syed", "Learn GCP"),
            new Todo("syed", "Learn Azure"));
    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'syed'")
    @RolesAllowed({"ADMIN","USER"})
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    public Todo retrieveTodosForASpecificUser(@PathVariable String username){
        return TODOS_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForASpecificUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Creating todo {} for user {}", todo, username);
    }

    @DeleteMapping("/users/{username}/todos/{id}")
    public void deleteTodo(@PathVariable String username, @PathVariable long id){
        logger.info("Deleting todo {} for user {}", id, username);
    }
  }

 record Todo(String username, String description) {}