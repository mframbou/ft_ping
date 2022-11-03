/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_hex.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:39:37 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:54 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

static char	*dec_to_base(unsigned int nbr, char *base)
{
	size_t			j;
	char			*result;
	char			*temp_result;

	temp_result = malloc (sizeof (char) * 40);
	j = -1 ;
	while (++j < 40)
		temp_result[j] = '\0';
	j -= 2;
	if (nbr == 0)
		temp_result[--j] = base[0];
	while (nbr > 0)
	{
		temp_result[--j] = base[nbr % ft_printf_strlen(base)];
		nbr /= ft_printf_strlen(base);
	}
	result = ft_printf_strdup(&(temp_result[j]));
	free(temp_result);
	return (result);
}

int	ft_printf_hex_min(va_list *args, int fd)
{
	unsigned int	nbr;
	char			*nb_str;
	int				hex_len;

	nbr = va_arg(*args, unsigned int);
	nb_str = dec_to_base(nbr, "0123456789abcdef");
	ft_printf_putstr_fd(nb_str, fd);
	hex_len = ft_printf_strlen(nb_str);
	free(nb_str);
	return (hex_len);
}

int	ft_printf_hex_maj(va_list *args, int fd)
{
	unsigned int	nbr;
	char			*nb_str;
	int				hex_len;

	nbr = va_arg(*args, unsigned int);
	nb_str = dec_to_base(nbr, "0123456789ABCDEF");
	ft_printf_putstr_fd(nb_str, fd);
	hex_len = ft_printf_strlen(nb_str);
	free(nb_str);
	return (hex_len);
}
