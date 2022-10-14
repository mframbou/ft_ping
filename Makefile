run:
	@echo building container
	docker build -t ft_nm ./
	@echo starting container
	docker run -v "$(PWD)/srcs":/ft_nm -it ft_nm