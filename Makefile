NAME = ft_ping

run:
	@echo building container
	docker build -t $(NAME) ./
	@echo starting container
	docker run -v "$(PWD)/srcs":/mframbou -it $(NAME)