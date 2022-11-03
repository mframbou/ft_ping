/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 10:34:26 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:55 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ft_printf_local.h"

int	print_arg(char *str, va_list *args, t_conversions *conversions_list, int fd)
{
	int	i;
	int	total;

	if (*str == '%')
		str++;
	total = -1;
	i = 0;
	while (conversions_list[i].type != 0)
	{
		if (conversions_list[i].type == *str)
		{
			total = conversions_list[i].print_data(args, fd);
			break ;
		}
		i++;
	}
	return (total);
}

void	init_conversions_tab(t_conversions *tab)
{
	tab[0].type = 'c';
	tab[0].print_data = &ft_printf_char;
	tab[1].type = 's';
	tab[1].print_data = &ft_printf_str;
	tab[2].type = 'p';
	tab[2].print_data = &ft_printf_pointer;
	tab[3].type = 'd';
	tab[3].print_data = &ft_printf_integer;
	tab[4].type = 'i';
	tab[4].print_data = &ft_printf_integer;
	tab[5].type = 'u';
	tab[5].print_data = &ft_printf_unsigned_int;
	tab[6].type = 'x';
	tab[6].print_data = &ft_printf_hex_min;
	tab[7].type = 'X';
	tab[7].print_data = &ft_printf_hex_maj;
	tab[8].type = '%';
	tab[8].print_data = &ft_printf_percent;
	tab[9].type = 0;
	tab[9].print_data = NULL;
}

int	parse_print_string(char *str, va_list *args,
	t_conversions *conversions_list, int fd)
{
	int	printed_chars;
	int	total;

	total = 0;
	printed_chars = 0;
	while (*str)
	{
		if (*str == '%')
		{
			printed_chars = print_arg((char *) str, args, conversions_list, fd);
			if (printed_chars != -1)
			{
				str += 2;
				total += printed_chars;
				continue ;
			}
		}
		write(1, str++, fd);
		total++;
	}
	return (total);
}

int	ft_printf(const char *str, ...)
{
	va_list			args;
	t_conversions	*conversions_list;
	int				total;

	va_start(args, str);
	conversions_list = malloc (sizeof(t_conversions) * (9 + 1));
	init_conversions_tab(conversions_list);
	total = parse_print_string((char *)str, &args, \
								conversions_list, STDOUT_FILENO);
	free(conversions_list);
	return (total);
}

int	ft_printf_fd(int fd, const char *str, ...)
{
	va_list			args;
	t_conversions	*conversions_list;
	int				total;

	va_start(args, str);
	conversions_list = malloc (sizeof(t_conversions) * (9 + 1));
	init_conversions_tab(conversions_list);
	total = parse_print_string((char *)str, &args, \
								conversions_list, fd);
	free(conversions_list);
	return (total);
}
