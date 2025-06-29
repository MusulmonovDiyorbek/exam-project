import { Module } from '@nestjs/common';
import { ResultsService } from './results.service';
import { ResultsController } from './results.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Result } from './entities/result.entity';
import { Assignment } from 'src/assignment/entities/assignment.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Result, Assignment])],
  controllers: [ResultsController],
  providers: [ResultsService],
})
export class ResultsModule { }
 