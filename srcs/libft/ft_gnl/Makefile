SRCS = get_next_line_utils.c get_next_line.c

OBJS = $(SRCS:.c=.o)

CPUS ?= $(shell sysctl -n hw.ncpu || echo 1)
MAKEFLAGS += --jobs=$(CPUS)	# I'm fast as fuck boi

NAME = libft_gnl.a

CC = gcc -Wall -Wextra -Werror

SHELL = zsh
AQUA = \033[0;96m
AQUA_BOLD = \033[1;96m
PURPLE = \033[0;95m
PURPLE_BOLD = \033[1;95m
GREEN = \033[0;92m
GREEN_BOLD = \033[1;92m
GREEN_UNDRLINE = \033[4;32m
RED = \033[0;91m
IRED = \033[0;31m
RED_BOLD = \033[1;91m
SAME_LINE = \033[0G\033[2K
RESET = \033[0m
YELLOW = \033[0;33m

%.o: %.c
	@$(CC) -c $< -o $@
	@echo -n "$(SAME_LINE)$(AQUA)Compiling $(AQUA_BOLD)$<$(RESET)"

$(NAME):	$(OBJS)
	@echo
	@echo "$(PURPLE)Linking $(PURPLE)*.o into $(PURPLE_BOLD)$(NAME)$(RESET)"
ifndef NO_LIB
# Only link if needed
	@ ar rc $(NAME) $(OBJS)
endif
	@echo "$(GREEN_BOLD)Done compiling $(GREEN_UNDERLINE)$(NAME)$(RESET)"

all:		$(NAME)

clean:
	@rm -f $(OBJS)
	@echo "$(YELLOW)$(NAME): $(RED)Removing $(IRED)*.o$(RESET)"

fclean:		clean
	@rm -f $(NAME)
	@echo "$(YELLOW)$(NAME): $(RED)Removing $(IRED)$(NAME)$(RESET)"

re:			fclean all

.PHONY:	all clean fclean re
