<img src="https://user-images.githubusercontent.com/31453761/202922257-fdd9f598-9658-4715-bde7-4c3ecd3d0f8f.svg" width=70% height=70%>

This project aims to implement a minimalist blockchain running an alternative puzzle algorithm to Bitcoin Proof of Work (PoW) called [Proof of Interaction (PoI)](https://hal.archives-ouvertes.fr/hal-02479891v2/document).  
This new puzzle does not consume nearly as much energy as PoW as it is based on network communication delay instead of raw compute. This is the first implementation of the method.  

### Usage

We use [Task](https://taskfile.dev/) as a task runner. You can install it from [here](https://taskfile.dev/installation/).  
You can run the following tasks with `task <task_name>`:

```
task -l   
task: Available tasks for this project:
* build:        Build the go binary.
* check:        Run fmt+lint+test tasks in parallel.
* docker:       Build and run the docker image.
* fmt:          Format the go source files.
* lint:         Run .golangci.yaml linting rules.
* run:          Run the go program.
* test:         Run all the go tests.
```

The ambula node is written in [Go](https://go.dev/). You will need to install [golangci-lint](https://golangci-lint.run/usage/install/) cli for the lint task.  
You can look at the `Taskfile.yaml` file and the [Task documentation](https://taskfile.dev/usage/) for more infos about tasks.  

## Contribute

Look at our [coding conventions](https://github.com/pacokleitz/ambula/wiki/Coding-conventions) and how to [install our git pre-hooks](https://github.com/pacokleitz/ambula/wiki/Pre-hooks) to ensure you conform to it. 

## Paper

Jean-Philippe Abegg, Quentin Bramas, Thomas Noel. Blockchain using Proof-of-Interaction. 2021. ⟨[hal-02479891v2](https://hal.archives-ouvertes.fr/hal-02479891v2/document)⟩

## Mentions

https://github.com/dogecoin/dogecoin/issues/2059   

