/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_integer.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:33:54 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:54 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

static unsigned int	set_pos_if_neg(int nbr)
{
	long	pos_nbr;

	if (nbr < 0)
	{
		pos_nbr = (long) -nbr;
	}
	else
		pos_nbr = ((long) nbr);
	return ((unsigned int) pos_nbr);
}

static char	*dec_to_base(int nbr, char *base)
{
	size_t			j;
	unsigned int	pnum;
	char			*result;
	char			*temp_result;

	temp_result = malloc (sizeof (char) * 40);
	j = -1 ;
	while (++j < 40)
		temp_result[j] = '\0';
	j -= 2;
	pnum = set_pos_if_neg(nbr);
	if (pnum == 0)
		temp_result[--j] = base[0];
	while (pnum > 0)
	{
		temp_result[--j] = base[pnum % ft_printf_strlen(base)];
		pnum /= ft_printf_strlen(base);
	}
	if (nbr < 0)
		temp_result[--j] = '-';
	result = ft_printf_strdup(&(temp_result[j]));
	free(temp_result);
	return (result);
}

int	ft_printf_integer(va_list *args, int fd)
{
	char	*str;
	int		str_len;

	str = dec_to_base(va_arg(*args, int), "0123456789");
	ft_printf_putstr_fd(str, fd);
	str_len = ft_printf_strlen(str);
	free(str);
	return (str_len);
}
