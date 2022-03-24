import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { domainToASCII } from 'url';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // Generate de password hash
    const hash = await argon.hash(dto.password);
    try {
      // save new user on DB with the hashed password

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hash,
        },
      });
      delete user.hash;

      //return saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        // P2002 é um codigo para duplicatas nos registros
        if (error.code === 'P2002') {
          throw new ForbiddenException('credentials taken');
        }
      }
    }
  }

  async signin(dto: AuthDto) {
    //find a user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    //if user dont exists throw exception
    if (!user) {
      throw new ForbiddenException('credential incorrect');
    }
    // compare password
    const passwordCorreta = await argon.verify(user.hash, dto.password);
    //iff password tive errado jgoa um exceção
    if (!passwordCorreta) {
      throw new ForbiddenException('credential incorrect');
    }
    // retornar o usuario
    delete user.hash;
    return user;
  }
}

// pra escolher qual variaveis aparecem dentro de um user, depois de data:{}, pode escrever select: {} com as variaveis que voce QUER que Sejam Retornadas.
