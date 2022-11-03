/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/06 20:29:27 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

static int	get_nbr_len(int nb)
{
	int		len;
	long	pos_nb;

	pos_nb = nb;
	if (pos_nb < 0)
	{
		len = 2;
		pos_nb = -pos_nb;
	}
	else
		len = 1;
	pos_nb /= 10;
	while (pos_nb > 0)
	{
		len++;
		pos_nb /= 10;
	}
	return (len);
}

// Do first outside of loop in case n == 0
// Leave \0 at the end
// Return current index in case string is not full
// = Starts with terminating character
// Dup the result and free the temp one (so return val can be freed)
char	*ft_itoa(int n)
{
	char	*res;
	int		i;
	long	pos_nb;
	int		nbr_len;

	nbr_len = get_nbr_len(n);
	res = malloc(sizeof(char) * (nbr_len + 1));
	i = nbr_len - 1;
	pos_nb = n;
	if (!res)
		return (NULL);
	if (n < 0)
	{
		pos_nb = -pos_nb;
		res[0] = '-';
	}
	res[i--] = (pos_nb % 10) + '0';
	pos_nb /= 10;
	while (pos_nb > 0 && i >= 0)
	{
		res[i--] = (pos_nb % 10) + '0';
		pos_nb /= 10;
	}
	res[nbr_len] = '\0';
	return (res);
}
