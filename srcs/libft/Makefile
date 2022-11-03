SRCS = 	\
		chars/ft_isalnum.c	chars/ft_isalpha.c	chars/ft_isascii.c	chars/ft_isdigit.c \
		chars/ft_isprint.c	chars/ft_isspace.c	chars/ft_tolower.c	chars/ft_toupper.c \
\
		conversions/ft_atoi.c	conversions/ft_itoa.c	conversions/ft_atol.c \
\
		lists/ft_lstadd_back.c	lists/ft_lstadd_front.c	lists/ft_lstclear.c	lists/ft_lstdelone.c \
		lists/ft_lstiter.c		lists/ft_lstlast.c		lists/ft_lstmap.c	lists/ft_lstnew.c \
		lists/ft_lstsize.c \
\
		memory/ft_bzero.c	memory/ft_calloc.c	memory/ft_memchr.c	memory/ft_memcmp.c \
		memory/ft_memcpy.c	memory/ft_memmove.c	memory/ft_memset.c	memory/ft_realloc.c \
\
		print/ft_putchar_fd.c	print/ft_putendl_fd.c	print/ft_putnbr_fd.c	print/ft_putstr_fd.c \
\
		string_arrays/ft_free_str_array.c	string_arrays/ft_split_single.c		string_arrays/ft_split.c \
		string_arrays/ft_concat_str_array.c	string_arrays/ft_sort_str_array.c \
\
		strings/ft_strchr.c		strings/ft_strcmp.c		strings/ft_strdup.c		strings/ft_striteri.c \
		strings/ft_strjoin.c	strings/ft_strlcat.c	strings/ft_strlcpy.c	strings/ft_strlen.c \
		strings/ft_strmapi.c	strings/ft_strncmp.c	strings/ft_strnstr.c	strings/ft_strrchr.c \
		strings/ft_strtrim.c	strings/ft_substr.c		strings/ft_insert_str.c	strings/ft_rm_char.c \
		strings/ft_rm_substr.c \
\
		parsing/ft_is_valid_nbr.c	parsing/ft_is_str_number.c	parsing/ft_is_valid_nbr.c	parsing/ft_print_errors.c

ifndef NO_GNL
	FT_GNL =	ft_gnl/get_next_line.o			ft_gnl/get_next_line_utils.o
endif

ifndef NO_FT_PRINTF
	FT_PRINTF =	ft_printf/ft_libfunctions.o		ft_printf/ft_printf_char.o		ft_printf/ft_printf_hex.o \
				ft_printf/ft_printf_integer.o 	ft_printf/ft_printf_percent.o	ft_printf/ft_printf_pointer.o \
				ft_printf/ft_printf_str.o		ft_printf/ft_printf_unsigned_int.o ft_printf/ft_printf.o
endif

OBJS = $(SRCS:.c=.o)

#CPUS ?= $(shell sysctl -n hw.ncpu || echo 1)
#MAKEFLAGS += --jobs=1	# To avoid scrambled view

NAME = libft.a

HEADERS = libft.h

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
BLUE = \033[0;94m
BLUE_BOLD = \033[1;94m

, := , # to print a coma

%.o: %.c
	@$(CC) -c $< -o $@
	@echo -n "$(SAME_LINE)$(AQUA)Compiling $(AQUA_BOLD)$<$(RESET)"

$(NAME): $(if $(FT_GNL), $(FT_GNL)) $(if $(FT_PRINTF), $(FT_PRINTF)) $(OBJS)
	@echo
	@echo "$(PURPLE)Linking	$(PURPLE)*.o\
$(if $(FT_GNL),$(,)gnl)\
$(if $(FT_PRINTF),$(,)ft_printf) \
into $(PURPLE_BOLD)$(NAME)$(RESET)"

	@echo "$(YELLOW)INFO: You can remove gnl or ft_printf using the flags NO_GNL and NO_FT_PRINTF$(RESET)"
	@ar rc $(NAME) \
$(if $(FT_GNL), $(FT_GNL)) \
$(if $(FT_PRINTF), $(FT_PRINTF)) \
$(OBJS)

	@echo "$(GREEN_BOLD)Done compiling $(GREEN_UNDERLINE)$(NAME)$(RESET)"

all:		$(NAME)

clean:
	@rm -f $(OBJS)
	@echo "$(YELLOW)$(NAME): $(RED)Removing $(IRED)*.o$(RESET)"
	@make -C ft_printf clean
	@make -C ft_gnl clean

fclean:		clean
	@rm -f $(NAME)
	@echo "$(YELLOW)$(NAME): $(RED)Removing $(IRED)$(NAME)$(RESET)"
	@make -C ft_printf fclean
	@make -C ft_gnl fclean

re:			fclean all

$(FT_GNL):
	@echo "$(BLUE)Compiling $(BLUE_BOLD)ft_gnl$(RESET)"
	@$(MAKE) -C ft_gnl NO_LIB=1

$(FT_PRINTF):
	@echo "$(BLUE)Compiling $(BLUE_BOLD)ft_printf$(RESET)"
	@$(MAKE) -C ft_printf NO_LIB=1

.PHONY:	all clean fclean re bonus