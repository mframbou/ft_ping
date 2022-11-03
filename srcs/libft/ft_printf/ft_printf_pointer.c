/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_pointer.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:20:18 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:54 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

static char	*dec_to_base(uintptr_t nbr, char *base)
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

int	ft_printf_pointer(va_list *args, int fd)
{
	uintptr_t	ptr;
	char		*ptr_address;
	int			ptr_len;

	ptr = (uintptr_t) va_arg(*args, void *);
	ptr_address = dec_to_base(ptr, "0123456789abcdef");
	ft_printf_putstr_fd("0x", fd);
	ft_printf_putstr_fd(ptr_address, fd);
	ptr_len = ft_printf_strlen("0x") + ft_printf_strlen(ptr_address);
	free(ptr_address);
	return (ptr_len);
}
