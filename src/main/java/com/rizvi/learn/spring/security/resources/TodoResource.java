package com.rizvi.learn.spring.security.resources;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    public Todo retrieveTodosForASpecificUser(@PathVariable String username){
        return TODOS_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForASpecificUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Creating todo {} for user {}", todo, username);
    }
}

 record Todo(String username, String description) {}