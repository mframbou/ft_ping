/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_char.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:14:27 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:53 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

int	ft_printf_char(va_list *args, int fd)
{
	ft_printf_putchar_fd((char) va_arg(*args, int), fd);
	return (1);
}
